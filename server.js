import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt-nodejs';
import cors from 'cors';
import knex from 'knex';

// Initialize knex with DATABASE_URL and SSL config for Render Postgres
const db = knex({
  client: 'pg',
  connection: {
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }, // This allows connecting to Render's managed Postgres
  },
});

const app = express();
app.use(bodyParser.json());
app.use(cors());

app.get('/', (req, res) => {
  db.select('*').from('users')
    .then(users => res.json(users))
    .catch(err => res.status(400).json('unable to fetch users'));
});

app.post('/signin', (req, res) => {
  db.select('email', 'hash').from('login')
    .where('email', '=', req.body.email)
    .then(data => {
      if (data.length) {
        const isValid = bcrypt.compareSync(req.body.password, data[0].hash);
        if (isValid) {
          return db.select('*').from('users')
            .where('email', '=', req.body.email)
            .then(user => {
              res.json(user[0]);
            })
            .catch(() => res.status(400).json('unable to get user'));
        } else {
          res.status(400).json('wrong credentials');
        }
      } else {
        res.status(400).json('wrong credentials');
      }
    })
    .catch(() => res.status(400).json('wrong credentials'));
});

app.post('/register', (req, res) => {
  const { email, name, password } = req.body;
  const hash = bcrypt.hashSync(password);
  db.transaction(trx => {
    trx.insert({
      hash: hash,
      email: email
    })
      .into('login')
      .returning('email')
      .then(loginEmail => {
        return trx('users')
          .returning('*')
          .insert({
            email: loginEmail[0].email,
            name: name,
            joined: new Date()
          })
          .then(user => {
            res.json(user[0]);
          });
      })
      .then(trx.commit)
      .catch(trx.rollback);
  })
    .catch(() => res.status(404).json('unable to register'));
});

app.get('/profile/:id', (req, res) => {
  const { id } = req.params;
  db.select('*').from('users').where({ id })
    .then(users => {
      if (users.length) {
        res.json(users[0]);
      } else {
        res.status(400).json('Not Found');
      }
    })
    .catch(() => res.status(400).json('error getting users'));
});

app.put('/image', (req, res) => {
  const { id } = req.body;
  db('users').where('id', '=', id)
    .increment('entries', 1)
    .returning('entries')
    .then(entries => {
      res.json(entries[0]);
    })
    .catch(() => res.status(400).json('unable to get entries'));
});

// Use PORT from environment or default to 3000
app.listen(process.env.PORT || 3000, () => {
  console.log(`app is running on port ${process.env.PORT || 3000}`);
});