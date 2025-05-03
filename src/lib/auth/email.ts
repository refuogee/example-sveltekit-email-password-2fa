import { AuthModels } from "$lib/schema/auth";

export function verifyEmailInput(email: string): boolean {
	return /^.+@.+\..+$/.test(email) && email.length < 256;
}

export async function checkEmailAvailability(email: string): Promise<boolean> {
	
	const row = await AuthModels.User.find({ email });

	

	if (!row) {
        console.log("this is the error")
		throw new Error();
	}

	return row.length === 0;
}
