import { totpBucket } from "$lib/auth/2fa";
import { fail, redirect } from "@sveltejs/kit";
import { getUserTOTPKey } from "$lib/auth/user";
import { verifyTOTP } from "@oslojs/otp";
import { setSessionAs2FAVerified } from "$lib/auth/session";

import type { Actions, RequestEvent } from "./$types";

export async function load(event: RequestEvent) {
	if (event.locals.session === null || event.locals.user === null) {
		return redirect(302, "/login");
	}
	if (!event.locals.user.emailVerified) {
		return redirect(302, "/verify-email");
	}
	if (!event.locals.user.registered2FA) {
		return redirect(302, "/2fa/setup");
	}
	if (event.locals.session.twoFactorVerified) {
		return redirect(302, "/");
	}
	return {};
}

export const actions: Actions = {
	default: action
};

async function action(event: RequestEvent) {
	if (event.locals.session === null || event.locals.user === null) {
		return fail(401, {
			message: "Not authenticated"
		});
	}
	if (!event.locals.user.emailVerified || !event.locals.user.registered2FA || event.locals.session.twoFactorVerified) {
		return fail(403, {
			message: "Forbidden"
		});
	}
	if (!totpBucket.check(event.locals.user._id, 1)) {
		return fail(429, {
			message: "Too many requests"
		});
	}

	const formData = await event.request.formData();
	const code = formData.get("code");
	if (typeof code !== "string") {
		return fail(400, {
			message: "Invalid or missing fields"
		});
	}
	if (code === "") {
		return fail(400, {
			message: "Enter your code"
		});
	}
	if (!totpBucket.consume(event.locals.user._id, 1)) {
		return fail(429, {
			message: "Too many requests"
		});
	}
	const totpKey = getUserTOTPKey(event.locals.user._id);
	if (totpKey === null) {
		return fail(403, {
			message: "Forbidden"
		});
	}
	if (!verifyTOTP(totpKey, 30, 6, code)) {
		return fail(400, {
			message: "Invalid code"
		});
	}
	totpBucket.reset(event.locals.user._id);
	setSessionAs2FAVerified(event.locals.session._id);
	return redirect(302, "/");
}
