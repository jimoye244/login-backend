import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import sqlite3 from 'sqlite3';
import cors from 'cors';
import session from 'express-session';

const app = express();
app.use(cors());
app.use(express.json());

app.use(session({
  secret: 'your-secret-key',  // Use a secure key for session encryption
  resave: false,
  saveUninitialized: true
}));

app.get("/",function(request,response){
   response.send("Hello World!")
})

const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Could not open database', err);
  } else {
    console.log('Connected to SQLite database');
  }
});

// Initialize the users table
db.run(
  'CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT)',
  (err) => {
    if (err) {
      console.error('Error creating table', err);
    }
 });

// Register route
app.post('/api/register', (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  db.run(
    'INSERT INTO users (email, password) VALUES (?, ?)',
    [email, hashedPassword],
    function (err) {
      if (err) {
        return res.status(500).json({ message: 'Error saving user' });
      }
      res.status(201).json({ message: 'User registered successfully' });
   });
});

// Login route
app.post('/api/login', (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  // Fetch the user by email
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
    //console.log("My User ..." + [email] + " " +email);
    if (err) {
      return res.status(500).json({ message: 'Error fetching user' });
    }
    if (!row) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Compare the provided password with the stored hashed password
    const isPasswordValid = bcrypt.compareSync(password, row.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    req.session.userId = email;
    console.log(" Request Session " +req.session.userId);
      return res.status(200).json({ message: 'Login successful' });
    // return res.status(200).json({ message: 'Login successful', redirect: '/api/landing' });
    //return res.redirect('/api/landing');
  });
});

// Landing Page Route (After login)
app.get('/api/landing', (req: Request, res: Response) => {
  console.log("While in Landing .... " + req.session.userId);
  console.log("While in Landing .... " + req.session.toString());
  if (!req.session.userId) {
    return res.status(401).json({ message: 'Unauthorized. Please log in.' });
  }
  // If the user is logged in, show the landing page
  res.send(`
    <h1>Welcome to the Landing Page, ${req.session.userId}!</h1>
    <form action="/api/logout" method="POST">
      <button type="submit">Logout</button>
    </form>
  `);
});

// Logout Route
app.post('/api/logout', (req: Request, res: Response) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: 'Failed to logout' });
    }
    res.redirect('/');  // Redirect to home or login page
  });
});


app.post('/logina', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, row) => {
    if (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    } else if (row) {
      // Successful login
      res.status(200).send('Login Successful');
    } else {
      // Invalid credentials
      res.status(401).send('Invalid username or password');
    }
  });
});

// Retrieve route
app.post('/api/retrieve', (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
  }
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.get(
    'SELECT user FROM users WHERE email = ? AND password = ?', [email, hashedPassword],
    function (err) {
      if (err) {
        return res.status(500).json({ message: 'Error retrieving user' });
      } else if (row) {
        // Successful login
        res.status(200).json({message: 'Login Successful'});
      } else {
        // Invalid credentials
        res.status(401).json({message :'Invalid username or password'});
      }
     // res.status(200).json({ message: 'User retrieved successfully' });
    }
  );
});

export const getUserByEmail = async (email: string) => {
  const user = await db.get('SELECT * FROM users WHERE email = ?', email);
  return user;
};

// Password Reset route
app.post('/api/reset-password', (req: Request, res: Response) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) {
    return res.status(400).json({ message: 'Email and new password are required' });
  }

  const hashedPassword = bcrypt.hashSync(newPassword, 10);
  db.run(
    'UPDATE users SET password = ? WHERE email = ?',
    [hashedPassword, email],
    function (err) {
      if (err) {
        return res.status(500).json({ message: 'Error resetting password' });
      }
      res.status(200).json({ message: 'Password reset successfully' });
    }
  );
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
