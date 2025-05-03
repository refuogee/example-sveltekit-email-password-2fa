import type { ObjectId } from "mongoose";

export type SID<T> = T & { _id: string };
export type OID<T> = T & { _id: ObjectId };
