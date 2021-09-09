require('dotenv').config()
const port = process.argv[2] || process.env.PORT || 8765
const crypto = require('crypto')
const { CloudantV1 } = require('@ibm-cloud/cloudant')
const express = require('express')
const helmet = require('helmet')
const expressSession = require('express-session')
const Gun = require('gun')
require('gun/sea')
require('gun/axe')

const app = express()

app.use(Gun.serve)

app.disable('x-powered-by')
app.set('trust proxy', 1)
app.use(express.json())
app.use(helmet())
app.use(
  expressSession({
    resave: true,
    saveUninitialized: true,
    secret: 'just-some-secret',
    name: 'note-gun-server',
  })
)

const server = app.listen(port)
// (latter) add Amazon S3 support
Gun({
  web: server,
})
// const client = faunadb.Client({ secret: process.env.fauna_db_secret })

app.post('/authorize', async (req, res) => {
  if (!req.body && !req.body.password)
    res.status(400).json({ msg: 'password is required' })
  if (!req.body && req.body.username)
    res.status(400).json({ msg: 'username is required' })

  const { password, username } = req.body

  if (typeof password !== 'string')
    res.status(400).json({ msg: 'password must be type of string' })
  if (typeof username !== 'string')
    res.status(400).json({ msg: 'username must be type of string' })

  // * Need to store somewhere this hashed password and username
  // * Look up some free databases (could use amazon s3 ?)
  // eslint-disable-next-line
  const client = new CloudantV1.newInstance({ serviceName: 'CLOUDANT' })
  const secureUser = {
    _id: username,
    username,
    password: crypto.createHash('sha512').update(password).digest('hex'),
  }
  try {
    // check if user already exists in database
    const user = await client.getDocument({
      db: process.env.DB_NAME,
      docId: username,
    })

    // need to check if provided password is the same as from db
    if (secureUser.password !== user.result.password)
      return res.json({ ok: false, msg: 'wrong username or password' })

    return res.json({ ok: true, user: user.result })
  } catch (error) {
    if (error.message !== 'not_found')
      return res.status(500).json({
        ok: false,
        error: 'Something went completely wrong, if you see this',
      })

    // created user in db
    const { result } = await client.postDocument({
      db: process.env.DB_NAME,
      document: {
        _id: username,
        username,
        password: crypto.createHash('sha512').update(password).digest('hex'),
        createdAt: Date.now(),
      },
    })
    if (!result.ok)
      return res.status(400).json({
        ok: false,
        error: 'Something went wrong when was creating user',
      })

    res.status(201).json({ ok: true, result: secureUser })
  }
})

console.log('Server started on port ' + port + ' with /gun')
