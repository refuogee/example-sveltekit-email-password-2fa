import { db } from "./../db";
import { encodeHexLowerCase } from "@oslojs/encoding";
import { generateRandomOTP } from "./../utils";
import { sha256 } from "@oslojs/crypto/sha2";

import type { RequestEvent } from "@sveltejs/kit";
import type { IAuth } from "$lib/interfaces/auth";
import { AuthModels } from "$lib/schema/auth";

export function createPasswordResetSession(token: string, userId: string, email: string): IAuth.PasswordResetSession {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	const session: IAuth.PasswordResetSession = {
		_id: sessionId,
		userId,
		email,
		expiresAt: new Date(Date.now() + 1000 * 60 * 10),
		code: generateRandomOTP(),
		emailVerified: false,
		twoFactorVerified: false
	};
	db.execute("INSERT INTO password_reset_session (id, user_id, email, code, expires_at) VALUES (?, ?, ?, ?, ?)", [
		session._id,
		session.userId,
		session.email,
		session.code,
		Math.floor(session.expiresAt.getTime() / 1000)
	]);
	return session;
}

export function validatePasswordResetSessionToken(token: string): IAuth.PasswordResetSessionValidationResult {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	const row = db.queryOne(
		`SELECT password_reset_session.id, password_reset_session.user_id, password_reset_session.email, password_reset_session.code, password_reset_session.expires_at, password_reset_session.email_verified, password_reset_session.two_factor_verified,
user.id, user.email, user.username, user.email_verified, IIF(user.totp_key IS NOT NULL, 1, 0)
FROM password_reset_session INNER JOIN user ON user.id = password_reset_session.user_id
WHERE password_reset_session.id = ?`,
		[sessionId]
	);
	if (row === null) {
		return { session: null, user: null };
	}
	const session: IAuth.PasswordResetSession = {
		_id: row.string(0),
		userId: row.string(1),
		email: row.string(2),
		code: row.string(3),
		expiresAt: new Date(row.number(4) * 1000),
		emailVerified: Boolean(row.number(5)),
		twoFactorVerified: Boolean(row.number(6))
	};
	const user: IAuth.User = {
		_id: row.string(7),
		email: row.string(8),
		username: row.string(9),
		emailVerified: Boolean(row.number(10)),
		registered2FA: Boolean(row.number(11))
	};
	if (Date.now() >= session.expiresAt.getTime()) {
		db.execute("DELETE FROM password_reset_session WHERE id = ?", [session._id]);
		return { session: null, user: null };
	}
	return { session, user };
}

export function setPasswordResetSessionAsEmailVerified(sessionId: string): void {
	db.execute("UPDATE password_reset_session SET email_verified = 1 WHERE id = ?", [sessionId]);
}

export function setPasswordResetSessionAs2FAVerified(sessionId: string): void {
	db.execute("UPDATE password_reset_session SET two_factor_verified = 1 WHERE id = ?", [sessionId]);
}

export async function invalidateUserPasswordResetSessions(userId: string): Promise<void> {
	await AuthModels.PasswordResetSession.deleteMany({ userId });
}

export function validatePasswordResetSessionRequest(event: RequestEvent): IAuth.PasswordResetSessionValidationResult {
	const token = event.cookies.get("password_reset_session") ?? null;
	if (token === null) {
		return { session: null, user: null };
	}
	const result = validatePasswordResetSessionToken(token);
	if (result.session === null) {
		deletePasswordResetSessionTokenCookie(event);
	}
	return result;
}

export function setPasswordResetSessionTokenCookie(event: RequestEvent, token: string, expiresAt: Date): void {
	event.cookies.set("password_reset_session", token, {
		expires: expiresAt,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export function deletePasswordResetSessionTokenCookie(event: RequestEvent): void {
	event.cookies.set("password_reset_session", "", {
		maxAge: 0,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export function sendPasswordResetEmail(email: string, code: string): void {
	console.log(`To ${email}: Your reset code is ${code}`);
}
