'use strict'
const { PrismaClient } = require('@prisma/client')
const yup = require('yup')
const createDOMPurify = require('dompurify')
const { JSDOM } = require('jsdom')
const verify = require('jsonwebtoken/verify')
const jwks = require('jwks-rsa')

const prisma = new PrismaClient()

const noteCreateSchema = yup.object().shape({
  title: yup.string().min(1).max(255),
  content: yup.string().nullable(),
})
const noteUpdateSchema = yup.object().shape({
  title: yup.string().nullable(),
  content: yup.string().nullable(),
})
const keys = jwks({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5,
  jwksUri: 'https://bogdankostyuk.eu.auth0.com/.well-known/jwks.json',
})

const purify = (() => {
  const { window } = new JSDOM()
  const DOMPurify = createDOMPurify(window)

  return (object) =>
    Object.keys(object).reduce(
      (acc, key) => ({ ...acc, [key]: DOMPurify.sanitize(object[key]) }),
      {}
    )
})()

const getUser = (event) =>
  new Promise((resolve, reject) => {
    if (!event.headers.Authorization)
      return reject(new Error('no authorization was provided'))

    const token = event.headers.Authorization.split(' ')[1]
    const tokenHeaders = token.split('.')[0]
    let kid
    try {
      kid = JSON.parse(Buffer.from(tokenHeaders, 'base64').toString()).kid
    } catch (error) {
      return reject(new Error('400'))
    }

    keys.getSigningKey(kid).then(({ rsaPublicKey, alg }) => {
      try {
        verify(token, rsaPublicKey, {
          algorithms: alg,
          audience: 'note-app-api',
          issuer: [
            'https://bogdankostyuk.eu.auth0.com',
            'https://bogdankostyuk.eu.auth0.com/',
          ],
        })

        const name = event.headers.Name || event.headers.name || null
        const email = event.headers.Email || event.headers.email || null
        const picture = event.headers.Picture || event.headers.picture || null

        if (!name || !email || !picture)
          return reject(new Error('not enough data was not provided'))

        return resolve({
          email,
          name,
          picture,
        })
      } catch (error) {
        reject(new Error(error.message))
      }
    })
  })

module.exports.getAllNotes = async (event) => {
  if (!event.headers.Authorization) return { statusCode: 401 }

  let user

  try {
    user = await getUser(event)
  } catch (error) {
    console.log(error)
    return {
      statusCode: 400,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
    }
  }

  const notes = await prisma.note.findMany({
    where: { owner: { email: { equals: user.email } } },
  })

  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true,
    },
    body: JSON.stringify({ data: notes }),
  }
}

module.exports.getOneNote = async (event) => {
  if (!event.headers.Authorization) return { statusCode: 401 }
  if (!event.pathParameters.id || isNaN(event.pathParameters.id))
    return {
      statusCode: 400,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
    }

  const id = parseInt(event.pathParameters.id)

  let user

  try {
    user = await getUser(event)
  } catch (error) {
    return {
      statusCode: 400,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
    }
  }

  if (!user) return { statusCode: 400 }
  const note = await prisma.note.findUnique({
    where: { id },
    include: { owner: true },
  })

  if (!note) return { statusCode: 200, body: JSON.stringify({ data: note }) }
  if (note.owner.email !== user.email)
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
      body: JSON.stringify({ data: null }),
    }

  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true,
    },
    body: JSON.stringify({ data: note }),
  }
}

module.exports.createNote = async (event) => {
  if (!event.body) return { statusCode: 400 }

  let user

  try {
    user = await getUser(event)
  } catch (error) {
    return {
      statusCode: 400,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
    }
  }

  let validNote

  try {
    validNote = noteCreateSchema.validateSync(event.body)
  } catch (error) {
    return {
      statusCode: 400,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
    }
  }

  const secureNote = purify(validNote)

  const createdNote = await prisma.note.create({
    data: {
      ...secureNote,
      owner: {
        connectOrCreate: {
          where: { email: user.email },
          create: {
            name: user.name,
            email: user.email,
            picture: user.picture || '',
          },
        },
      },
    },
  })

  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true,
    },
    body: JSON.stringify({ data: createdNote }),
  }
}

module.exports.updateNote = async (event) => {
  if (!event.body) return { statusCode: 400 }
  if (!event.pathParameters.id || isNaN(event.pathParameters.id))
    return {
      statusCode: 400,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
    }

  const id = parseInt(event.pathParameters.id)
  let user

  try {
    user = await getUser(event)
  } catch (error) {
    return {
      statusCode: error.res.statusCode,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
      body: JSON.stringify({ msg: error.message }),
    }
  }

  let validNote

  try {
    validNote = noteUpdateSchema.validateSync(event.body)
  } catch (error) {
    return {
      statusCode: 400,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
    }
  }

  const secureNote = purify(validNote)

  const note = await prisma.note.findUnique({
    where: { id },
    include: { owner: true },
  })

  if (!note) return { statusCode: 400 }
  // basically i need to return 401, but just to confuse the attackers i will return 400
  if (note.owner.email !== user.email) return { statusCode: 400 }

  const updatedNote = await prisma.note.update({
    where: { id },
    data: { ...secureNote },
  })

  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true,
    },
    body: JSON.stringify({ data: updatedNote }),
  }
}

module.exports.deleteNote = async (event) => {
  if (!event.pathParameters.id || isNaN(event.pathParameters.id))
    return {
      statusCode: 400,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
    }

  const id = parseInt(event.pathParameters.id)
  let user

  try {
    user = await getUser(event)
  } catch (error) {
    return {
      statusCode: error.res.statusCode,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
      body: JSON.stringify({ msg: error.message }),
    }
  }

  const note = await prisma.note.findUnique({
    where: { id },
    include: { owner: true },
  })

  if (!note) return { statusCode: 400 }
  // basically i need to return 401, but just to confuse the attackers i will return 400
  if (note.owner.email !== user.email) return { statusCode: 400 }

  const deletedNote = await prisma.note.delete({
    where: { id },
  })

  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true,
    },
    body: JSON.stringify({ data: deletedNote }),
  }
}
