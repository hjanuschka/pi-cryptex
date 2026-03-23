import { StringEnum } from "@mariozechner/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { Type, type Static } from "@sinclair/typebox";
import { spawnSync } from "node:child_process";
import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync } from "node:crypto";
import { promises as fs } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";

const KEYCHAIN_SERVICE = "pi-cryptex";
const PASSWORD_ENV_VAR = "PI_CRYPTEX_PASSWORD";
const VAULT_DIRECTORY = ".cryptex";
const VAULT_FILE = "vault.v1.enc";
const VAULT_DEFAULT_GIT_PATH = ".cryptex/vault.v1.enc";
const PI_STATE_KEY_PREFIX = "pi_state:";

// Includes pi-multi-pass account registry by default.
const PI_DEFAULT_BACKUP_PATHS = ["auth.json", "multi-pass.json", "settings.json"];
const PI_DEFAULT_RESTORE_PATHS = ["auth.json", "multi-pass.json"];

const CryptexVaultParamsSchema = Type.Object({
	action: StringEnum(["set", "set_many", "get", "get_many", "delete", "list", "nuke", "rotate_password"] as const),
	key: Type.Optional(Type.String({ description: "Secret key name" })),
	value: Type.Optional(Type.String({ description: "Secret value for action=set" })),
	items: Type.Optional(
		Type.Record(Type.String(), Type.String(), {
			description: "Map of key/value pairs for action=set_many",
		}),
	),
	keys: Type.Optional(Type.Array(Type.String(), { description: "Requested keys for action=get_many" })),
	reveal: Type.Optional(
		Type.Boolean({
			description: "If true, return plaintext values in tool output. Use with care.",
		}),
	),
	newPassword: Type.Optional(Type.String({ description: "New master password for action=rotate_password" })),
});

const CryptexPiStateParamsSchema = Type.Object({
	action: StringEnum(["backup", "restore"] as const),
	profile: Type.Optional(
		Type.String({
			description: "Named profile for backup/restore. Stored under key pi_state:<profile>. Default: default",
		}),
	),
	paths: Type.Optional(
		Type.Array(Type.String(), {
			description:
				"Relative paths under ~/.pi/agent. Backup default: auth.json,multi-pass.json,settings.json. Restore default: auth.json,multi-pass.json",
		}),
	),
	overwrite: Type.Optional(
		Type.Boolean({
			description: "For restore. If true, overwrite existing files in ~/.pi/agent.",
		}),
	),
});

const CryptexGitSyncParamsSchema = Type.Object({
	action: StringEnum(["push", "pull"] as const),
	repoUrl: Type.Optional(
		Type.String({
			description:
				"Remote git URL (ssh/https) for a dedicated cryptex repo. If omitted in push, push in current git repo.",
		}),
	),
	branch: Type.Optional(Type.String({ description: "Optional git branch" })),
	remotePath: Type.Optional(
		Type.String({
			description: "Path to vault file inside git repo. Default: .cryptex/vault.v1.enc",
		}),
	),
	commitMessage: Type.Optional(
		Type.String({
			description: "Commit message for push. Optional.",
		}),
	),
});

type CryptexVaultParams = Static<typeof CryptexVaultParamsSchema>;
type CryptexPiStateParams = Static<typeof CryptexPiStateParamsSchema>;
type CryptexGitSyncParams = Static<typeof CryptexGitSyncParamsSchema>;

interface VaultEntry {
	value: string;
	createdAt: string;
	updatedAt: string;
}

interface VaultData {
	version: 1;
	updatedAt: string;
	items: Record<string, VaultEntry>;
}

interface VaultEnvelope {
	version: 1;
	kdf: "scrypt";
	salt: string;
	iv: string;
	tag: string;
	ciphertext: string;
}

interface PiStateBundleFile {
	encoding: "base64";
	content: string;
	mode: number;
	modifiedAt: string;
}

interface PiStateBundle {
	version: 1;
	createdAt: string;
	source: "pi-cryptex";
	files: Record<string, PiStateBundleFile>;
}

const nowIso = () => new Date().toISOString();

const createEmptyVault = (): VaultData => ({
	version: 1,
	updatedAt: nowIso(),
	items: {},
});

const normalizePath = (cwd: string, absolutePath: string): string => {
	const rel = path.relative(cwd, absolutePath);
	return rel && rel !== "" ? rel : absolutePath;
};

const maskSecret = (value: string): string => {
	if (value.length <= 4) return "*".repeat(value.length || 1);
	return `${value.slice(0, 2)}***${value.slice(-2)}`;
};

const keychainAccount = (cwd: string): string => {
	const hash = createHash("sha256").update(cwd).digest("hex");
	return `project-${hash.slice(0, 24)}`;
};

const readPasswordFromKeychain = (cwd: string): string | undefined => {
	if (process.platform !== "darwin") return undefined;

	const result = spawnSync(
		"security",
		["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", keychainAccount(cwd), "-w"],
		{ encoding: "utf8" },
	);

	if (result.status !== 0) return undefined;
	const value = (result.stdout || "").trim();
	return value.length > 0 ? value : undefined;
};

const writePasswordToKeychain = (cwd: string, password: string): boolean => {
	if (process.platform !== "darwin") return false;

	const result = spawnSync(
		"security",
		[
			"add-generic-password",
			"-U",
			"-s",
			KEYCHAIN_SERVICE,
			"-a",
			keychainAccount(cwd),
			"-w",
			password,
		],
		{ encoding: "utf8" },
	);

	return result.status === 0;
};

const deriveKey = (password: string, salt: Buffer): Buffer => {
	return scryptSync(password, salt, 32) as Buffer;
};

const encryptVault = (vault: VaultData, password: string): string => {
	const salt = randomBytes(16);
	const iv = randomBytes(12);
	const key = deriveKey(password, salt);

	const cipher = createCipheriv("aes-256-gcm", key, iv);
	const plaintext = Buffer.from(JSON.stringify(vault), "utf8");
	const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	const tag = cipher.getAuthTag();

	const envelope: VaultEnvelope = {
		version: 1,
		kdf: "scrypt",
		salt: salt.toString("base64"),
		iv: iv.toString("base64"),
		tag: tag.toString("base64"),
		ciphertext: ciphertext.toString("base64"),
	};

	return JSON.stringify(envelope, null, 2);
};

const decryptVault = (raw: string, password: string): VaultData => {
	const envelope = JSON.parse(raw) as VaultEnvelope;

	if (!envelope || envelope.version !== 1 || envelope.kdf !== "scrypt") {
		throw new Error("Unsupported vault format");
	}

	const salt = Buffer.from(envelope.salt, "base64");
	const iv = Buffer.from(envelope.iv, "base64");
	const tag = Buffer.from(envelope.tag, "base64");
	const ciphertext = Buffer.from(envelope.ciphertext, "base64");
	const key = deriveKey(password, salt);

	const decipher = createDecipheriv("aes-256-gcm", key, iv);
	decipher.setAuthTag(tag);
	const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");

	const vault = JSON.parse(plaintext) as VaultData;
	if (!vault || vault.version !== 1 || typeof vault.items !== "object") {
		throw new Error("Invalid vault data");
	}

	return vault;
};

const readVault = async (vaultPath: string, password: string): Promise<VaultData> => {
	try {
		const encrypted = await fs.readFile(vaultPath, "utf8");
		return decryptVault(encrypted, password);
	} catch (error) {
		const err = error as NodeJS.ErrnoException;
		if (err.code === "ENOENT") return createEmptyVault();
		if (err.name === "SyntaxError") {
			throw new Error(`Vault at ${vaultPath} is not valid JSON`);
		}
		if (err.message.includes("Unsupported state or unable to authenticate data")) {
			throw new Error(`Unable to decrypt vault at ${vaultPath}. Wrong password or corrupted file.`);
		}
		throw err;
	}
};

const writeVault = async (vaultPath: string, vault: VaultData, password: string): Promise<void> => {
	const encrypted = encryptVault(vault, password);
	await fs.mkdir(path.dirname(vaultPath), { recursive: true });

	const tmpPath = `${vaultPath}.tmp-${Date.now()}-${process.pid}`;
	await fs.writeFile(tmpPath, encrypted, { encoding: "utf8", mode: 0o600 });
	await fs.rename(tmpPath, vaultPath);
};

const promptForNewPassword = async (ctx: ExtensionContext, title: string): Promise<string> => {
	if (!ctx.hasUI) {
		throw new Error(
			`No UI available. Set ${PASSWORD_ENV_VAR} or store a keychain password before using pi-cryptex in non-interactive mode.`,
		);
	}

	const pass1 = await ctx.ui.input(title, "Enter a master password");
	if (!pass1 || pass1.trim().length === 0) {
		throw new Error("Master password cannot be empty");
	}

	const pass2 = await ctx.ui.input("Confirm master password", "Re-enter the same password");
	if (pass1 !== pass2) {
		throw new Error("Passwords do not match");
	}

	return pass1;
};

const normalizeProfile = (profile: string | undefined): string => {
	const value = (profile || "default").trim();
	if (value.length === 0) return "default";
	if (!/^[a-zA-Z0-9._-]+$/.test(value)) {
		throw new Error("profile may only contain letters, numbers, dot, underscore, and dash");
	}
	return value;
};

const sanitizeRelativePath = (value: string, label: string): string => {
	const normalized = path.posix.normalize(value.trim().replaceAll("\\", "/"));
	if (!normalized || normalized === ".") {
		throw new Error(`${label} cannot be empty`);
	}
	if (normalized.startsWith("/") || normalized === ".." || normalized.startsWith("../")) {
		throw new Error(`Invalid ${label}: ${value}`);
	}
	return normalized;
};

const sanitizePiRelativePath = (value: string): string => sanitizeRelativePath(value, "paths entry");

const getPiAgentRoot = (): string => path.join(homedir(), ".pi", "agent");

const parsePiStateBundle = (raw: string): PiStateBundle => {
	const bundle = JSON.parse(raw) as PiStateBundle;
	if (!bundle || bundle.version !== 1 || bundle.source !== "pi-cryptex" || typeof bundle.files !== "object") {
		throw new Error("Invalid pi_state payload in vault");
	}
	return bundle;
};

const runGit = (cwd: string, args: string[]): string => {
	const result = spawnSync("git", args, {
		cwd,
		encoding: "utf8",
	});
	if (result.status !== 0) {
		const stderr = (result.stderr || "").trim();
		const stdout = (result.stdout || "").trim();
		const output = stderr || stdout || `git ${args.join(" ")} failed`;
		throw new Error(output);
	}
	return (result.stdout || "").trim();
};

const ensureFileExists = async (filePath: string, errorMessage: string): Promise<void> => {
	try {
		const stat = await fs.stat(filePath);
		if (!stat.isFile()) throw new Error(errorMessage);
	} catch (error) {
		const err = error as NodeJS.ErrnoException;
		if (err.code === "ENOENT") throw new Error(errorMessage);
		if (err.message === errorMessage) throw err;
		throw err;
	}
};

const backupPiStateIntoVault = async (
	ctx: ExtensionContext,
	vault: VaultData,
	vaultPath: string,
	password: string,
	profile: string,
	paths: string[],
) => {
	const piRoot = getPiAgentRoot();
	const bundle: PiStateBundle = {
		version: 1,
		createdAt: nowIso(),
		source: "pi-cryptex",
		files: {},
	};

	const missing: string[] = [];
	let added = 0;
	for (const rel of paths) {
		const abs = path.join(piRoot, rel);
		try {
			const stat = await fs.stat(abs);
			if (!stat.isFile()) {
				missing.push(rel);
				continue;
			}
			const content = await fs.readFile(abs);
			bundle.files[rel] = {
				encoding: "base64",
				content: content.toString("base64"),
				mode: stat.mode & 0o777,
				modifiedAt: new Date(stat.mtimeMs).toISOString(),
			};
			added += 1;
		} catch (error) {
			const err = error as NodeJS.ErrnoException;
			if (err.code === "ENOENT") {
				missing.push(rel);
				continue;
			}
			throw err;
		}
	}

	if (added === 0) {
		throw new Error(`No pi files found in ${piRoot}. Checked: ${paths.join(", ")}`);
	}

	const key = `${PI_STATE_KEY_PREFIX}${profile}`;
	const timestamp = nowIso();
	const existing = vault.items[key];
	vault.items[key] = {
		value: JSON.stringify(bundle),
		createdAt: existing?.createdAt ?? timestamp,
		updatedAt: timestamp,
	};
	vault.updatedAt = timestamp;
	await writeVault(vaultPath, vault, password);

	let text = `Backed up ${added} file(s) from ~/.pi/agent to key ${key}.`;
	if (missing.length > 0) {
		text += ` Missing: ${missing.join(", ")}.`;
	}
	text += ` Commit ${normalizePath(ctx.cwd, vaultPath)} to sync this backup.`;

	return {
		content: [{ type: "text" as const, text }],
		details: {
			action: "backup",
			profile,
			storedKey: key,
			count: added,
			missing,
		},
	};
};

const restorePiStateFromVault = async (
	vault: VaultData,
	profile: string,
	paths: string[],
	overwrite: boolean,
) => {
	const key = `${PI_STATE_KEY_PREFIX}${profile}`;
	const entry = vault.items[key];
	if (!entry) {
		return {
			content: [{ type: "text" as const, text: `No backup found for profile ${profile}.` }],
			details: { action: "restore", profile, restored: [], key },
		};
	}

	const bundle = parsePiStateBundle(entry.value);
	const piRoot = getPiAgentRoot();
	const missingInBundle: string[] = [];
	const skippedExisting: string[] = [];
	const restored: string[] = [];

	for (const rel of paths) {
		const file = bundle.files[rel];
		if (!file) {
			missingInBundle.push(rel);
			continue;
		}

		const abs = path.join(piRoot, rel);
		if (!overwrite) {
			try {
				await fs.access(abs);
				skippedExisting.push(rel);
				continue;
			} catch (error) {
				const err = error as NodeJS.ErrnoException;
				if (err.code !== "ENOENT") throw err;
			}
		}

		await fs.mkdir(path.dirname(abs), { recursive: true });
		const bytes = Buffer.from(file.content, "base64");
		await fs.writeFile(abs, bytes, { mode: 0o600 });
		await fs.chmod(abs, 0o600);
		restored.push(rel);
	}

	let text = `Restored ${restored.length} file(s) from ${key} into ~/.pi/agent.`;
	if (skippedExisting.length > 0) {
		text += ` Skipped existing (set overwrite=true to replace): ${skippedExisting.join(", ")}.`;
	}
	if (missingInBundle.length > 0) {
		text += ` Missing in backup: ${missingInBundle.join(", ")}.`;
	}
	if (restored.includes("auth.json") || restored.includes("multi-pass.json")) {
		text += " Restart pi if provider auth or pool state does not refresh immediately.";
	}

	return {
		content: [{ type: "text" as const, text }],
		details: {
			action: "restore",
			profile,
			key,
			restored,
			skippedExisting,
			missingInBundle,
		},
	};
};

export default function (pi: ExtensionAPI) {
	let cachedPassword: string | undefined;

	const vaultPathFor = (cwd: string) => path.join(cwd, VAULT_DIRECTORY, VAULT_FILE);

	const resolvePassword = async (ctx: ExtensionContext): Promise<string> => {
		if (cachedPassword) return cachedPassword;

		const fromEnv = process.env[PASSWORD_ENV_VAR];
		if (fromEnv && fromEnv.trim().length > 0) {
			cachedPassword = fromEnv;
			return cachedPassword;
		}

		const fromKeychain = readPasswordFromKeychain(ctx.cwd);
		if (fromKeychain) {
			cachedPassword = fromKeychain;
			return cachedPassword;
		}

		const created = await promptForNewPassword(ctx, "Create pi-cryptex master password");
		cachedPassword = created;

		if (writePasswordToKeychain(ctx.cwd, created)) {
			ctx.ui.notify("Saved pi-cryptex password to macOS Keychain", "info");
		} else {
			ctx.ui.notify(`Password not stored in keychain. Consider setting ${PASSWORD_ENV_VAR}.`, "warning");
		}

		return created;
	};

	pi.registerCommand("cryptex-password", {
		description: "Create or rotate the pi-cryptex master password for this project",
		handler: async (_args, ctx) => {
			const newPassword = await promptForNewPassword(ctx, "Set pi-cryptex master password");
			cachedPassword = newPassword;
			if (writePasswordToKeychain(ctx.cwd, newPassword)) {
				ctx.ui.notify("pi-cryptex password saved to macOS Keychain", "info");
			} else {
				ctx.ui.notify(`Could not write keychain entry. Use ${PASSWORD_ENV_VAR} as fallback.`, "warning");
			}
		},
	});

	pi.registerCommand("cryptex-info", {
		description: "Show where pi-cryptex stores its encrypted vault",
		handler: async (_args, ctx) => {
			const vaultPath = vaultPathFor(ctx.cwd);
			ctx.ui.notify(`Vault file: ${normalizePath(ctx.cwd, vaultPath)}`, "info");
		},
	});

	pi.registerCommand("cryptex-backup-pi", {
		description: "Backup ~/.pi/agent auth,multi-pass,settings into cryptex profile",
		handler: async (args, ctx) => {
			const profile = normalizeProfile(args || "default");
			const paths = PI_DEFAULT_BACKUP_PATHS.map(sanitizePiRelativePath);
			const password = await resolvePassword(ctx);
			const vaultPath = vaultPathFor(ctx.cwd);
			const vault = await readVault(vaultPath, password);
			const result = await backupPiStateIntoVault(ctx, vault, vaultPath, password, profile, paths);
			const line = result.content[0];
			ctx.ui.notify(line.type === "text" ? line.text : "Backup finished", "info");
		},
	});

	pi.registerCommand("cryptex-restore-pi", {
		description: "Restore ~/.pi/agent auth,multi-pass from cryptex profile",
		handler: async (args, ctx) => {
			const profile = normalizeProfile(args || "default");
			const paths = PI_DEFAULT_RESTORE_PATHS.map(sanitizePiRelativePath);
			const password = await resolvePassword(ctx);
			const vaultPath = vaultPathFor(ctx.cwd);
			const vault = await readVault(vaultPath, password);
			const result = await restorePiStateFromVault(vault, profile, paths, true);
			const line = result.content[0];
			ctx.ui.notify(line.type === "text" ? line.text : "Restore finished", "info");
		},
	});

	pi.registerTool({
		name: "cryptex_vault",
		label: "Cryptex Vault",
		description:
			"Manage encrypted credentials in the local vault file. Actions: set, set_many, get, get_many, delete, list, nuke, rotate_password.",
		promptSnippet: "Manage encrypted project credentials in .cryptex/vault.v1.enc.",
		promptGuidelines: [
			"Use this tool when the user asks to store or retrieve credentials for this project.",
			"Avoid reveal=true unless the user explicitly asks to print plaintext secrets.",
		],
		parameters: CryptexVaultParamsSchema,
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const input = params as CryptexVaultParams;
			const password = await resolvePassword(ctx);
			const vaultPath = vaultPathFor(ctx.cwd);
			const vault = await readVault(vaultPath, password);

			switch (input.action) {
				case "set": {
					if (!input.key || input.key.trim().length === 0) throw new Error("action=set requires key");

					let value = input.value;
					if ((!value || value.length === 0) && ctx.hasUI) {
						value = await ctx.ui.input(`Value for ${input.key}`, "Enter secret value");
					}
					if (!value || value.length === 0) throw new Error("action=set requires value");

					const timestamp = nowIso();
					const existing = vault.items[input.key];
					vault.items[input.key] = {
						value,
						createdAt: existing?.createdAt ?? timestamp,
						updatedAt: timestamp,
					};
					vault.updatedAt = timestamp;
					await writeVault(vaultPath, vault, password);

					return {
						content: [{ type: "text", text: `Stored key ${input.key} in ${normalizePath(ctx.cwd, vaultPath)}.` }],
						details: { action: "set", key: input.key, created: !existing },
					};
				}

				case "set_many": {
					if (!input.items || Object.keys(input.items).length === 0) {
						throw new Error("action=set_many requires a non-empty items map");
					}

					const timestamp = nowIso();
					const updatedKeys: string[] = [];
					for (const [key, value] of Object.entries(input.items)) {
						const existing = vault.items[key];
						vault.items[key] = {
							value: String(value),
							createdAt: existing?.createdAt ?? timestamp,
							updatedAt: timestamp,
						};
						updatedKeys.push(key);
					}
					vault.updatedAt = timestamp;
					await writeVault(vaultPath, vault, password);

					return {
						content: [{ type: "text", text: `Stored ${updatedKeys.length} secret(s).` }],
						details: { action: "set_many", keys: updatedKeys },
					};
				}

				case "get": {
					if (!input.key || input.key.trim().length === 0) throw new Error("action=get requires key");
					const entry = vault.items[input.key];
					if (!entry) {
						return {
							content: [{ type: "text", text: `Key ${input.key} not found.` }],
							details: { action: "get", key: input.key, found: false },
						};
					}

					if (input.reveal) {
						return {
							content: [{ type: "text", text: entry.value }],
							details: { action: "get", key: input.key, found: true, revealed: true, updatedAt: entry.updatedAt },
						};
					}

					return {
						content: [{ type: "text", text: `${input.key}=${maskSecret(entry.value)} (hidden)` }],
						details: { action: "get", key: input.key, found: true, revealed: false, updatedAt: entry.updatedAt },
					};
				}

				case "get_many": {
					const requested = input.keys && input.keys.length > 0 ? input.keys : Object.keys(vault.items).sort();
					const found: Record<string, string> = {};
					for (const key of requested) {
						const entry = vault.items[key];
						if (!entry) continue;
						found[key] = input.reveal ? entry.value : maskSecret(entry.value);
					}
					return {
						content: [{ type: "text", text: JSON.stringify(found, null, 2) }],
						details: { action: "get_many", revealed: Boolean(input.reveal), count: Object.keys(found).length },
					};
				}

				case "delete": {
					if (!input.key || input.key.trim().length === 0) throw new Error("action=delete requires key");
					if (!vault.items[input.key]) {
						return {
							content: [{ type: "text", text: `Key ${input.key} not found.` }],
							details: { action: "delete", key: input.key, deleted: false },
						};
					}

					delete vault.items[input.key];
					vault.updatedAt = nowIso();
					await writeVault(vaultPath, vault, password);

					return {
						content: [{ type: "text", text: `Deleted key ${input.key}.` }],
						details: { action: "delete", key: input.key, deleted: true },
					};
				}

				case "list": {
					const keys = Object.keys(vault.items).sort();
					return {
						content: [{ type: "text", text: keys.length === 0 ? "No secrets stored yet." : keys.join("\n") }],
						details: { action: "list", count: keys.length },
					};
				}

				case "nuke": {
					vault.items = {};
					vault.updatedAt = nowIso();
					await writeVault(vaultPath, vault, password);
					return { content: [{ type: "text", text: "Deleted all stored keys." }], details: { action: "nuke" } };
				}

				case "rotate_password": {
					let nextPassword = input.newPassword;
					if ((!nextPassword || nextPassword.length === 0) && ctx.hasUI) {
						nextPassword = await promptForNewPassword(ctx, "Rotate pi-cryptex master password");
					}
					if (!nextPassword || nextPassword.length === 0) {
						throw new Error("action=rotate_password requires newPassword");
					}

					await writeVault(vaultPath, vault, nextPassword);
					cachedPassword = nextPassword;
					if (writePasswordToKeychain(ctx.cwd, nextPassword)) {
						ctx.ui.notify("Updated pi-cryptex password in macOS Keychain", "info");
					}

					return { content: [{ type: "text", text: "Master password rotated." }], details: { action: "rotate_password" } };
				}
			}
		},
	});

	pi.registerTool({
		name: "cryptex_pi_state",
		label: "Cryptex Pi State",
		description:
			"Backup and restore pi login state and pi-multi-pass config via the encrypted vault. Actions: backup, restore.",
		promptSnippet: "Backup/restore ~/.pi/agent auth and multi-pass config into cryptex vault profiles.",
		promptGuidelines: [
			"Use this tool when user asks to migrate pi logins/accounts between machines.",
			"By default backup includes auth.json,multi-pass.json,settings.json and restore includes auth.json,multi-pass.json.",
		],
		parameters: CryptexPiStateParamsSchema,
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const input = params as CryptexPiStateParams;
			const profile = normalizeProfile(input.profile);
			const password = await resolvePassword(ctx);
			const vaultPath = vaultPathFor(ctx.cwd);
			const vault = await readVault(vaultPath, password);

			if (input.action === "backup") {
				const paths = (input.paths && input.paths.length > 0 ? input.paths : PI_DEFAULT_BACKUP_PATHS).map(
					sanitizePiRelativePath,
				);
				return backupPiStateIntoVault(ctx, vault, vaultPath, password, profile, paths);
			}

			const paths = (input.paths && input.paths.length > 0 ? input.paths : PI_DEFAULT_RESTORE_PATHS).map(
				sanitizePiRelativePath,
			);
			return restorePiStateFromVault(vault, profile, paths, Boolean(input.overwrite));
		},
	});

	pi.registerTool({
		name: "cryptex_git_sync",
		label: "Cryptex Git Sync",
		description:
			"Sync the encrypted vault file to git. Actions: push, pull. Supports current repo push or dedicated remote repo sync.",
		promptSnippet: "Push/pull .cryptex/vault.v1.enc to or from git repositories.",
		promptGuidelines: [
			"Use this tool when user asks to store cryptex vault in git, similar to fastlane cryptex.",
			"For pull, repoUrl is required.",
		],
		parameters: CryptexGitSyncParamsSchema,
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const input = params as CryptexGitSyncParams;
			const vaultPath = vaultPathFor(ctx.cwd);

			if (input.action === "push") {
				await ensureFileExists(vaultPath, `Vault file not found at ${vaultPath}. Store at least one secret first.`);
				const commitMessage =
					input.commitMessage?.trim() || `[pi-cryptex] update vault ${new Date().toISOString()}`;

				if (!input.repoUrl || input.repoUrl.trim().length === 0) {
					// Push in current repository.
					runGit(ctx.cwd, ["rev-parse", "--is-inside-work-tree"]);
					const localVaultPath = sanitizeRelativePath(path.relative(ctx.cwd, vaultPath), "vault path");
					runGit(ctx.cwd, ["add", "--", localVaultPath]);
					const status = runGit(ctx.cwd, ["status", "--porcelain", "--", localVaultPath]);
					if (!status.trim()) {
						return {
							content: [{ type: "text", text: "Vault is already up to date in current git repository." }],
							details: { action: "push", mode: "local", changed: false },
						};
					}

					runGit(ctx.cwd, ["commit", "-m", commitMessage, "--", localVaultPath]);
					if (input.branch && input.branch.trim().length > 0) {
						runGit(ctx.cwd, ["push", "origin", input.branch.trim()]);
					} else {
						runGit(ctx.cwd, ["push"]);
					}

					return {
						content: [{ type: "text", text: `Pushed ${localVaultPath} from current repository.` }],
						details: { action: "push", mode: "local", changed: true },
					};
				}

				// Push to dedicated remote repo.
				const repoUrl = input.repoUrl.trim();
				const branch = input.branch?.trim();
				const remotePath = sanitizeRelativePath(input.remotePath || VAULT_DEFAULT_GIT_PATH, "remotePath");
				const workdir = await fs.mkdtemp(path.join(tmpdir(), "pi-cryptex-"));
				try {
					runGit(ctx.cwd, ["clone", "--depth", "1", repoUrl, workdir]);
					if (branch && branch.length > 0) {
						try {
							runGit(workdir, ["checkout", branch]);
						} catch {
							runGit(workdir, ["checkout", "-b", branch]);
						}
					}

					const target = path.join(workdir, remotePath);
					await fs.mkdir(path.dirname(target), { recursive: true });
					const bytes = await fs.readFile(vaultPath);
					await fs.writeFile(target, bytes, { mode: 0o600 });

					runGit(workdir, ["add", "--", remotePath]);
					const status = runGit(workdir, ["status", "--porcelain", "--", remotePath]);
					if (!status.trim()) {
						return {
							content: [{ type: "text", text: `Remote vault at ${remotePath} is already up to date.` }],
							details: { action: "push", mode: "remote", changed: false, repoUrl },
						};
					}

					runGit(workdir, ["commit", "-m", commitMessage, "--", remotePath]);
					if (branch && branch.length > 0) {
						runGit(workdir, ["push", "origin", branch]);
					} else {
						runGit(workdir, ["push"]);
					}

					return {
						content: [{ type: "text", text: `Pushed vault to ${repoUrl} (${remotePath}).` }],
						details: { action: "push", mode: "remote", changed: true, repoUrl, remotePath, branch },
					};
				} finally {
					await fs.rm(workdir, { recursive: true, force: true });
				}
			}

			if (!input.repoUrl || input.repoUrl.trim().length === 0) {
				throw new Error("action=pull requires repoUrl");
			}

			const repoUrl = input.repoUrl.trim();
			const branch = input.branch?.trim();
			const remotePath = sanitizeRelativePath(input.remotePath || VAULT_DEFAULT_GIT_PATH, "remotePath");
			const workdir = await fs.mkdtemp(path.join(tmpdir(), "pi-cryptex-"));
			try {
				runGit(ctx.cwd, ["clone", "--depth", "1", repoUrl, workdir]);
				if (branch && branch.length > 0) {
					try {
						runGit(workdir, ["checkout", branch]);
					} catch {
						throw new Error(`Branch ${branch} not found in ${repoUrl}`);
					}
				}

				const source = path.join(workdir, remotePath);
				await ensureFileExists(source, `Remote vault not found at ${remotePath} in ${repoUrl}`);
				await fs.mkdir(path.dirname(vaultPath), { recursive: true });
				const bytes = await fs.readFile(source);
				await fs.writeFile(vaultPath, bytes, { mode: 0o600 });
				await fs.chmod(vaultPath, 0o600);

				return {
					content: [
						{
							type: "text",
							text: `Pulled vault from ${repoUrl} (${remotePath}) to ${normalizePath(ctx.cwd, vaultPath)}.`,
						},
					],
					details: { action: "pull", repoUrl, remotePath, branch },
				};
			} finally {
				await fs.rm(workdir, { recursive: true, force: true });
			}
		},
	});
}
