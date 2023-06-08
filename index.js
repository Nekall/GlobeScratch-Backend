import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import dotenv from "dotenv";
dotenv.config();
import Airtable from 'airtable';
const base = new Airtable({ apiKey: process.env.AIRTABLE_API_KEY }).base(process.env.AIRTABLE_BASE_ID);

const PORT = process.env.PORT || 3001;

const app = express();

console.log(await base.table("users").select().all());

app.get("/", async (_, res) => {
    res.send("GlobeScratch API is running...");
});

app.listen(PORT, () => {
    console.log(`server is ready on port: http://localhost:${PORT}`);
});