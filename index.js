import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import dotenv from "dotenv";
dotenv.config();

const PORT = process.env.PORT || 3001;

const app = express();

app.get("/", async (req, res) => {
    res.send("GlobeScratch API is running...");
});

app.listen(PORT, () => {
    console.log(`server is ready on port: http://localhost:${PORT}`);
  });