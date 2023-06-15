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
  const form = `
    <style>
      .container {
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
      }

      .form-container {
        max-width: 400px;
        padding: 20px;
        border: 1px solid #ccc;
        border-radius: 4px;
        background-color: #f2f2f2;
      }

      .form-container label {
        display: block;
        margin-bottom: 10px;
        font-weight: bold;
      }

      .form-container input[type="text"],
      .form-container input[type="password"] {
        width: 100%;
        padding: 10px;
        margin-bottom: 20px;
        border: 1px solid #ccc;
        border-radius: 4px;
        box-sizing: border-box;
      }

      .form-container input[type="submit"] {
        background-color: #4caf50;
        color: white;
        padding: 10px 20px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
      }

      .error-message {
        max-width: 400px;
        padding: 20px;
        border: 1px solid #ff3333;
        border-radius: 4px;
        background-color: #ffe6e6;
        color: #ff3333;
        font-weight: bold;
      }
    </style>
    
    <div class="container">
      <div class="form-container">
        <form action="/error" method="GET">
          <label for="username">Nom d'utilisateur:</label>
          <input type="text" id="username" name="username" required>

          <label for="password">Mot de passe:</label>
          <input type="password" id="password" name="password" required>

          <input type="submit" value="Se connecter">
        </form>
      </div>
    </div>
  `;

  res.send(form);
});

app.get("/error", async (_, res) => {
  const errorMessage = `
    <style>
      .container {
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
      }

      .error-message {
        max-width: 400px;
        padding: 20px;
        border: 1px solid #ff3333;
        border-radius: 4px;
        background-color: #ffe6e6;
        color: #ff3333;
        font-weight: bold;
      }
    </style>
    
    <div class="container">
      <div class="error-message">
        Erreur : nom d'utilisateur ou mot de passe incorrect !
      </div>
    </div>
  `;

  res.send(errorMessage);
});

app.post("/signup", async (req, res) => {
  try {
    const { email, password, lastname, firstname, country } = req.body;
    const requiredFields = [email, password, lastname, firstname, country];

    if (requiredFields.some((field) => !field)) {
      return res.status(400).json({
        success: false,
        message: "Veuillez remplir tous les champs requis.",
      });
    }

    const existingUser = await base("users")
      .select({
        filterByFormula: `{email} = "${email}"`,
      })
      .all();

    if (existingUser.length > 0) {
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
          countries: "[]",
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

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Veuillez remplir tous les champs requis.",
    });
  }

  base("users")
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

      const user = records[0]?.fields;

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Aucun utilisateur trouvé avec cet email.",
        });
      }

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
    const userEmail = jwt.decode(jwtToken.split(" ")[1]).user.email;

    let user = await base("users")
      .select({
        filterByFormula: `{email} = "${userEmail}"`,
      })
      .all();

    if (user.length === 0) {
      return res.status(409).json({
        success: false,
        message: "Aucun compte avec cette adresse mail trouvé.",
      });
    }

    const updateUserFields = {
      email: req.body.email || user[0].fields.email,
      password: req.body.password
        ? await bcrypt.hash(req.body.password, saltRounds)
        : user[0].fields.password,
      firstname: req.body.firstname || user[0].fields.firstname,
      lastname: req.body.lastname || user[0].fields.lastname,
      country: req.body.country || user[0].fields.country,
      franceDpt: req.body.franceDpt || user[0].fields.franceDpt,
      countries: req.body.countries || user[0].fields.countries,
    };

    await base("users").update([
      {
        id: user[0].id,
        fields: updateUserFields,
      },
    ]);

    user = await base("users")
      .select({
        filterByFormula: `{email} = "${userEmail}"`,
      })
      .all();

    delete user[0].fields.password;

    res.status(200).json({
      success: true,
      message: "Compte modifié avec succès.",
      user: user[0].fields,
    });
  } catch (error) {
    console.error("Erreur lors de la modification du compte:", error);
    res.status(500).json({
      success: false,
      message: "Une erreur est survenue lors de la modification du compte.",
    });
  }
});

app.delete("/user", async (req, res) => {
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
    const userEmail = jwt.decode(jwtToken.split(" ")[1]).user.email;

    let user = await base("users")
      .select({
        filterByFormula: `{email} = "${userEmail}"`,
      })
      .all();

    if (user.length === 0) {
      return res.status(409).json({
        success: false,
        message: "Aucun compte trouvé.",
      });
    }

    await base("users").destroy([user[0].id]);

    res.status(200).json({
      success: true,
      message: "Compte supprimé avec succès.",
    });
  } catch (error) {
    console.error("Erreur lors de la suppression du compte:", error);
    res.status(500).json({
      success: false,
      message: "Une erreur est survenue lors de la suppression du compte.",
    });
  }
});

app.listen(PORT, () => {
  console.info(`server is ready on port: http://localhost:${PORT}`);
});
