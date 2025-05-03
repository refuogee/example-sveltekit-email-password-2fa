import type { SID } from "$lib/interfaces";
import type { IAuth } from "$lib/interfaces/auth";
import mongoose, { Model } from "mongoose";

const User: Model<SID<IAuth.User & { passwordHash: string; totp_key: Buffer; recoveryCode: Buffer }>> =
	mongoose.models["auth_user"] ||
	mongoose.model(
		"auth_user",
		new mongoose.Schema(
			{
				_id: String,
				email: { type: String, required: true },
				username: { type: String, required: true },
				passwordHash: { type: String, required: true },
				emailVerified: { type: Boolean, required: true },
				totp_key: { type: Buffer },
				recoveryCode: { type: Buffer, required: true }
			},
			{
				_id: false
			}
		)
	);

const Session =
	mongoose.models["session"] ||
	mongoose.model<SID<IAuth.Session>>(
		"session",
		new mongoose.Schema(
			{
				_id: String,
				userId: { type: String, required: true },
				expiresAt: { type: Date, required: true },
				twoFactorVerified: { type: Boolean, required: true }
			},
			{
				_id: false
			}
		)
	);

// CREATE TABLE email_verification_request (
//     id TEXT NOT NULL PRIMARY KEY,
//     user_id INTEGER NOT NULL REFERENCES user(id),
//     email TEXT NOT NULL,
//     code TEXT NOT NULL,
//     expires_at INTEGER NOT NULL
// );

const EmailVerificationRequest =
	mongoose.models["EmailVerificationRequest"] ||
	mongoose.model<SID<IAuth.EmailVerificationRequest>>(
		"EmailVerificationRequest",
		new mongoose.Schema(
			{
				_id: String,
				userId: { type: String, required: true },
				code: { type: String, required: true },
				email: { type: String, required: true },
				expiresAt: { type: Date, required: true }
			},
			{
				_id: false
			}
		)
	);

const PasswordResetSession =
	mongoose.models["PasswordResetSession"] ||
	mongoose.model<SID<IAuth.PasswordResetSession>>(
		"PasswordResetSession",
		new mongoose.Schema(
			{
				_id: String,
				userId: { type: String, required: true },
				email: { type: String, required: true },
				code: { type: String, required: true },
				expiresAt: { type: Date, required: true },
				emailVerified: { type: Boolean, required: true },
				twoFactorVerified: { type: Boolean, required: true }
			},
			{
				_id: false
			}
		)
	);

export const AuthModels = {
	User,
	Session,
	EmailVerificationRequest,
	PasswordResetSession
};
