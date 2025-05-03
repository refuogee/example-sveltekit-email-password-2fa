import { db } from "./../db";
import { encodeBase32LowerCaseNoPadding, encodeHexLowerCase } from "@oslojs/encoding";
import { sha256 } from "@oslojs/crypto/sha2";
import type { RequestEvent } from "@sveltejs/kit";
import type { IAuth } from "$lib/interfaces/auth";
import { AuthModels } from "$lib/schema/auth";

export async function validateSessionToken(token: string): Promise<IAuth.SessionValidationResult> {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));

	const session_data = await AuthModels.Session.findOne({ _id: sessionId });
	if (!session_data) {
		return { session: null, user: null };
	}

	const user_data = await AuthModels.User.findOne({ _id: session_data.userId });

	if (!user_data) {
		console.log("User not found");
		return { session: null, user: null };
	}

	const session: IAuth.Session = {
		_id: session_data._id,
		userId: session_data.userId,
		expiresAt: session_data.expiresAt,
		twoFactorVerified: session_data.twoFactorVerified
	};

	const user: IAuth.User = {
		_id: session_data.userId,
		email: user_data.email,
		username: user_data.username,
		emailVerified: user_data.emailVerified,
		registered2FA: session_data.twoFactorVerified
	};

	if (Date.now() >= session.expiresAt.getTime()) {
		await AuthModels.Session.deleteOne({ _id: session._id });
		return { session: null, user: null };
	}
	if (Date.now() >= session.expiresAt.getTime() - 1000 * 60 * 60 * 24 * 15) {
		session.expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30);
		await AuthModels.Session.updateOne(
			{ _id: session._id }, // filter by _id
			{ $set: { expiresAt: session.expiresAt } } // set the new expiresAt value
		);
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

export async function setSessionAs2FAVerified(sessionId: string): Promise<void> {
	await AuthModels.Session.updateOne({ _id: sessionId }, { $set: { twoFactorVerified: true } });
	// db.execute("UPDATE session SET two_factor_verified = 1 WHERE id = ?", [sessionId]);
}
