// See https://kit.svelte.dev/docs/types#app
// for information about these interfaces
import type { User } from "$lib/auth/user";
import type { Session } from "$lib/auth/session";

declare global {
	namespace App {
		// interface Error {}
		interface Locals {
			user: User | null;
			session: Session | null;
		}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

export {};
