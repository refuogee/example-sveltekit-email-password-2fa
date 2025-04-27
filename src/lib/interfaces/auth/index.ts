export namespace IAuth {
	export type User = {
		_id: string;
		email: string;
		username: string;
		emailVerified: boolean;
		registered2FA: boolean;
	};

	export type SessionFlags = {
		twoFactorVerified: boolean;
	};

	export type Session = SessionFlags & {
		_id: string;
		expiresAt: Date;
		userId: string;
	};

	export type SessionValidationResult = { session: Session; user: IAuth.User } | { session: null; user: null };

	export type RefillBucket = {
		count: number;
		refilledAt: number;
	};

	export type ExpiringBucket = {
		count: number;
		createdAt: number;
	};

	export type ThrottlingCounter = {
		timeout: number;
		updatedAt: number;
	};

	export type PasswordResetSession = {
		_id: string;
		userId: string;
		email: string;
		expiresAt: Date;
		code: string;
		emailVerified: boolean;
		twoFactorVerified: boolean;
	};

	export type PasswordResetSessionValidationResult =
		| { session: PasswordResetSession; user: IAuth.User }
		| { session: null; user: null };

	export type EmailVerificationRequest = {
		_id: string;
		userId: string;
		code: string;
		email: string;
		expiresAt: Date;
	};
}
