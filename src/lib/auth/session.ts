import { db } from "./../db";
import { encodeBase32LowerCaseNoPadding, encodeHexLowerCase } from "@oslojs/encoding";
import { sha256 } from "@oslojs/crypto/sha2";
import type { RequestEvent } from "@sveltejs/kit";
import type { IAuth } from "$lib/interfaces/auth";
import { AuthModels } from "$lib/schema/auth";

export function validateSessionToken(token: string): IAuth.SessionValidationResult {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	const row = db.queryOne(
		`
SELECT session.id, session.user_id, session.expires_at, session.two_factor_verified, user.id, user.email, user.username, user.email_verified, IIF(user.totp_key IS NOT NULL, 1, 0) FROM session
INNER JOIN user ON session.user_id = user.id
WHERE session.id = ?
`,
		[sessionId]
	);

	if (row === null) {
		return { session: null, user: null };
	}
	const session: IAuth.Session = {
		_id: row.string(0),
		userId: row.string(1),
		expiresAt: new Date(row.number(2) * 1000),
		twoFactorVerified: Boolean(row.number(3))
	};
	const user: IAuth.User = {
		_id: row.string(4),
		email: row.string(5),
		username: row.string(6),
		emailVerified: Boolean(row.number(7)),
		registered2FA: Boolean(row.number(8))
	};
	if (Date.now() >= session.expiresAt.getTime()) {
		db.execute("DELETE FROM session WHERE id = ?", [session._id]);
		return { session: null, user: null };
	}
	if (Date.now() >= session.expiresAt.getTime() - 1000 * 60 * 60 * 24 * 15) {
		session.expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30);
		db.execute("UPDATE session SET expires_at = ? WHERE session.id = ?", [
			Math.floor(session.expiresAt.getTime() / 1000),
			session._id
		]);
	}
	return { session, user };
}

export function invalidateSession(sessionId: string): void {
	db.execute("DELETE FROM session WHERE id = ?", [sessionId]);
}

export function invalidateUserSessions(userId: string): void {
	db.execute("DELETE FROM session WHERE user_id = ?", [userId]);
}

export function setSessionTokenCookie(event: RequestEvent, token: string, expiresAt: Date): void {
	event.cookies.set("session", token, {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		expires: expiresAt
	});
}

export function deleteSessionTokenCookie(event: RequestEvent): void {
	event.cookies.set("session", "", {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		maxAge: 0
	});
}

export function generateSessionToken(): string {
	const tokenBytes = new Uint8Array(20);
	crypto.getRandomValues(tokenBytes);
	const token = encodeBase32LowerCaseNoPadding(tokenBytes).toLowerCase();
	return token;
}

export async function createSession(token: string, userId: string, flags: IAuth.SessionFlags): Promise<IAuth.Session> {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));

	const session: IAuth.Session = {
		_id: sessionId,
		userId,
		expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
        
		twoFactorVerified: flags.twoFactorVerified
	};

	await AuthModels.Session.create({
		_id: session._id,
		userId: session.userId,
		expiresAt: session.expiresAt,
		twoFactorVerified: session.twoFactorVerified
	});

	return session;
}

export function setSessionAs2FAVerified(sessionId: string): void {
	db.execute("UPDATE session SET two_factor_verified = 1 WHERE id = ?", [sessionId]);
}
