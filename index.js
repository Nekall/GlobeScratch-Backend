import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();
import Airtable from "airtable";
const base = new Airtable({ apiKey: process.env.AIRTABLE_API_KEY }).base(
  process.env.AIRTABLE_BASE_ID
);

const PORT = process.env.PORT || 3001;
const saltRounds = 10;

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.get("/", async (_, res) => {
  res.send("GlobeScratch API is running...");
});

app.post("/signup", async (req, res) => {
  try {
    const { email, password, lastname, firstname, country } = req.body;
    if (!email || !password || !lastname || !firstname || !country) {
      return res.status(400).json({
        success: false,
        message: "Veuillez remplir tous les champs requis.",
      });
    }

    const user = await base("users")
      .select({
        filterByFormula: `{email} = "${email}"`,
      })
      .all();

    if (user.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Un utilisateur existe déjà avec cet email.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await base.table("users").create([
      {
        fields: {
          email,
          password: hashedPassword,
          firstname,
          lastname,
          country,
          franceDpt: "[]",
        },
      },
    ]);

    res.status(200).json({
      success: true,
      message: "Compte créé avec succès.",
    });
  } catch (error) {
    console.error("Erreur lors de la création du compte:", error);
    res.status(500).json({
      success: false,
      message: "Une erreur est survenue lors de la création du compte.",
    });
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({
      success: false,
      message: "Veuillez remplir tous les champs requis.",
    });

  let user = base("users")
    .select({
      filterByFormula: `{email} = "${email}"`,
    })
    .all((err, records) => {
      if (err) {
        console.error("Erreur lors de la récupération de l'utilisateur:", err);
        return res.status(500).json({
          success: false,
          message:
            "Une erreur est survenue lors de la récupération de l'utilisateur.",
        });
      }
      if (records.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Aucun utilisateur trouvé avec cet email.",
        });
      }
      const user = records[0].fields;
      bcrypt.compare(password, user.password, (err, result) => {
        if (err) {
          console.error(
            "Erreur lors de la comparaison des mots de passe:",
            err
          );
          return res.status(500).json({
            success: false,
            message:
              "Une erreur est survenue lors de la comparaison des mots de passe.",
          });
        }
        if (!result) {
          return res.status(401).json({
            success: false,
            message: "Mot de passe incorrect.",
          });
        }

        delete user.password;
        const token = jwt.sign({ user }, process.env.JWT_SECRET, {
          expiresIn: "30d",
        });
        res.status(200).json({
          success: true,
          message: "Connexion réussie.",
          token,
          user,
        });
      });
    });
});

app.put("/user", async (req, res) => {
  const jwtToken = req.headers.authorization;

  if (!jwtToken) {
    return res.status(401).json({
      success: false,
      message: "Vous devez être connecté pour effectuer cette action.",
    });
  }

  try {
    jwt.verify(jwtToken.split(" ")[1], process.env.JWT_SECRET);
  } catch (error) {
    console.error("Erreur lors de la vérification du token:", error);
    return res.status(401).json({
      success: false,
      message: "Vous devez être connecté pour effectuer cette action.",
    });
  }

  try {
    const user = await base("users")
      .select({
        filterByFormula: `{email} = "${
          jwt.decode(jwtToken.split(" ")[1]).user.email
        }"`,
      })
      .all();

    if (user.length === 0) {
      return res.status(409).json({
        success: false,
        message: "Aucun compte avec cette adresse mail trouvé.",
      });
    }

    await base("users").update([
      {
        id: user[0].id,
        fields: {
          email: req.body.email ? req.body.email : user[0].email,
          password: req.body.password
            ? await bcrypt.hash(req.body.password, saltRounds)
            : user[0].password,
          firstname: req.body.firstname
            ? req.body.firstname
            : user[0].firstname,
          lastname: req.body.lastname ? req.body.lastname : user[0].lastname,
          country: req.body.country ? req.body.country : user[0].country,
          franceDpt: req.body.franceDpt
            ? req.body.franceDpt
            : user[0].franceDpt,
        },
      },
    ]);

    res.status(200).json({
      success: true,
      message: "Compte modifié avec succès.",
    });
  } catch (error) {
    console.error("Erreur lors de la modification du compte:", error);
    res.status(500).json({
      success: false,
      message: "Une erreur est survenue lors de la modification du compte.",
    });
  }
});

app.listen(PORT, () => {
  console.log(`server is ready on port: http://localhost:${PORT}`);
});
