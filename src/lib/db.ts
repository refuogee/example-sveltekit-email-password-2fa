import { MONGO_URI } from "$env/static/private";
import mongoose from "mongoose";

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 2000;

export async function mongoConnect(): Promise<typeof mongoose | null> {
	if (mongoose.connection.readyState === 1) {
		// Already connected
		return mongoose;
	}

	let attempts = 0;

	while (attempts < MAX_RETRIES) {
		try {
			console.log(`📡 Attempt ${attempts + 1} to connect to MongoDB...`);

			console.time("Connecting to MongoDB");
			await mongoose.connect(MONGO_URI, {
				serverSelectionTimeoutMS: 5000,
                autoIndex: false,
			});
			console.timeEnd("Connecting to MongoDB");

			console.log(`Connected to MongoDB: ${mongoose.connection.name}`);

			return mongoose;
		} catch (err) {
			console.error(`Connection attempt ${attempts + 1} failed:`, err);
			attempts++;

			if (attempts < MAX_RETRIES) {
				console.log(`Retrying in ${RETRY_DELAY_MS / 1000} seconds...`);
				await new Promise((res) => setTimeout(res, RETRY_DELAY_MS));
			} else {
				console.error("Failed to connect to MongoDB after 3 attempts.");
			}
		}
	}
	return null;
}
