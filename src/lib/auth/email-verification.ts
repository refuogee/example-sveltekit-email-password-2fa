import { createId, generateRandomOTP } from "./../utils";
import { db } from "./../db";
import { ExpiringTokenBucket } from "./rate-limit";
import { encodeBase32 } from "@oslojs/encoding";

import type { RequestEvent } from "@sveltejs/kit";
import type { IAuth } from "$lib/interfaces/auth";
import type { SID } from "$lib/interfaces";
import { AuthModels } from "$lib/schema/auth";

export async function getUserEmailVerificationRequest(
	userId: string,
	id: string
): Promise<IAuth.EmailVerificationRequest> {
	const email_verification_request = await AuthModels.EmailVerificationRequest.findOne({
		_id: id,
		userId: userId
	}).select("_id userId code email expiresAt");

	if (!email_verification_request) {
		return email_verification_request;
	}

	const request: IAuth.EmailVerificationRequest = {
		_id: email_verification_request._id,
		userId: email_verification_request.userId,
		code: email_verification_request.code,
		email: email_verification_request.email,
		expiresAt: email_verification_request.expiresAt
	};
	return request;
}

export async function createEmailVerificationRequest(
	userId: string,
	email: string
): Promise<IAuth.EmailVerificationRequest> {
	deleteUserEmailVerificationRequest(userId);

	const _id = createId();

	const code = generateRandomOTP();
	const expiresAt = new Date(Date.now() + 1000 * 60 * 10);

	await AuthModels.EmailVerificationRequest.create({
		_id,
		userId,
		code,
		email,
		expiresAt
	});

	const request: SID<IAuth.EmailVerificationRequest> = {
		_id,
		userId,
		code,
		email,
		expiresAt
	};

	return request;
}

export function deleteUserEmailVerificationRequest(userId: string): void {
	AuthModels.EmailVerificationRequest.deleteMany({ userId });
}

export function sendVerificationEmail(email: string, code: string): void {
	console.log(`To ${email}: Your verification code is ${code}`);
}

export function setEmailVerificationRequestCookie(event: RequestEvent, request: IAuth.EmailVerificationRequest): void {
	event.cookies.set("email_verification", request._id, {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		expires: request.expiresAt
	});
}

export function deleteEmailVerificationRequestCookie(event: RequestEvent): void {
	event.cookies.set("email_verification", "", {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		maxAge: 0
	});
}

export async function getUserEmailVerificationRequestFromRequest(
	event: RequestEvent
): Promise<IAuth.EmailVerificationRequest | null> {
	if (event.locals.user === null) {
		return null;
	}

	const id = event.cookies.get("email_verification") ?? null;

	if (id === null) {
		return null;
	}

	const request = await getUserEmailVerificationRequest(event.locals.user._id, id);

	if (request === null) {
		deleteEmailVerificationRequestCookie(event);
	}
	return request;
}

export const sendVerificationEmailBucket = new ExpiringTokenBucket<string>(3, 60 * 10);
