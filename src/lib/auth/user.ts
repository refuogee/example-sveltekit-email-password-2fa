import type { IAuth } from "$lib/interfaces/auth";
import { AuthModels } from "$lib/schema/auth";
import { db } from "./../db";
import { createId, generateRandomRecoveryCode } from "./../utils";
import { decrypt, decryptToString, encrypt, encryptString } from "./encryption";
import { hashPassword } from "./password";

export function verifyUsernameInput(username: string): boolean {
	return username.length > 3 && username.length < 32 && username.trim() === username;
}

export async function createUser(email: string, username: string, password: string): Promise<IAuth.User> {
	const passwordHash = await hashPassword(password);
	const recoveryCode = generateRandomRecoveryCode();
	const encryptedRecoveryCode = encryptString(recoveryCode);

	const created_user = await AuthModels.User.create({
		_id: createId(),
		email,
		username,
		passwordHash,
		recoveryCode,
		encryptedRecoveryCode,
		emailVerified: false
	});

	if (!created_user) {
		throw new Error("Unexpected error");
	}

	const user: IAuth.User = {
		_id: created_user._id,
		username,
		email,
		emailVerified: false,
		registered2FA: false
	};
	return user;
}

export async function updateUserPassword(userId: string, password: string): Promise<void> {
	const passwordHash = await hashPassword(password);
	db.execute("UPDATE user SET password_hash = ? WHERE id = ?", [passwordHash, userId]);
}

export function updateUserEmailAndSetEmailAsVerified(userId: string, email: string): void {
	db.execute("UPDATE user SET email = ?, email_verified = 1 WHERE id = ?", [email, userId]);
}

export function setUserAsEmailVerifiedIfEmailMatches(userId: string, email: string): boolean {
	const result = db.execute("UPDATE user SET email_verified = 1 WHERE id = ? AND email = ?", [userId, email]);
	return result.changes > 0;
}

export function getUserPasswordHash(userId: string): string {
	const row = db.queryOne("SELECT password_hash FROM user WHERE id = ?", [userId]);
	if (row === null) {
		throw new Error("Invalid user ID");
	}
	return row.string(0);
}

export function getUserRecoverCode(userId: string): string {
	const row = db.queryOne("SELECT recovery_code FROM user WHERE id = ?", [userId]);
	if (row === null) {
		throw new Error("Invalid user ID");
	}
	return decryptToString(row.bytes(0));
}

export function getUserTOTPKey(userId: string): Uint8Array | null {
	const row = db.queryOne("SELECT totp_key FROM user WHERE id = ?", [userId]);
	if (row === null) {
		throw new Error("Invalid user ID");
	}
	const encrypted = row.bytesNullable(0);
	if (encrypted === null) {
		return null;
	}
	return decrypt(encrypted);
}

export function updateUserTOTPKey(userId: string, key: Uint8Array): void {
	const encrypted = encrypt(key);
	db.execute("UPDATE user SET totp_key = ? WHERE id = ?", [encrypted, userId]);
}

export function resetUserRecoveryCode(userId: string): string {
	const recoveryCode = generateRandomRecoveryCode();
	const encrypted = encryptString(recoveryCode);
	db.execute("UPDATE user SET recovery_code = ? WHERE id = ?", [encrypted, userId]);
	return recoveryCode;
}

export function getUserFromEmail(email: string): IAuth.User | null {
	const row = db.queryOne(
		"SELECT id, email, username, email_verified, IIF(totp_key IS NOT NULL, 1, 0) FROM user WHERE email = ?",
		[email]
	);
	if (row === null) {
		return null;
	}
	const user: IAuth.User = {
		_id: row.string(0),
		email: row.string(1),
		username: row.string(2),
		emailVerified: Boolean(row.number(3)),
		registered2FA: Boolean(row.number(4))
	};
	return user;
}
