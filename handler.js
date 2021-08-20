'use strict'
const { PrismaClient } = require('@prisma/client')
const axios = require('axios').default
const yup = require('yup')
const createDOMPurify = require('dompurify')
const { JSDOM } = require('jsdom')

const prisma = new PrismaClient()

const noteCreateSchema = yup.object().shape({
  title: yup.string().min(1).max(255),
  content: yup.string().nullable(),
})
const noteUpdateSchema = yup.object().shape({
  title: yup.string().nullable(),
  content: yup.string().nullable(),
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

module.exports.getAllNotes = async (event) => {
  if (!event.headers.Authorization) return { statusCode: 401 }

  let user

  try {
    const res = await axios.get('https://bogdankostyuk.eu.auth0.com/userinfo', {
      headers: { Authorization: event.headers.Authorization },
    })
    user = res.data
  } catch (error) {
    return {
      statusCode: error.res.statusCode,
      body: JSON.stringify({ msg: error.res.statusMessage }),
    }
  }

  if (!user.email) return { statusCode: 400 }
  const notes = await prisma.note.findMany({
    where: { owner: { email: { equals: user.email } } },
  })

  return {
    statusCode: 200,
    body: JSON.stringify({ data: notes }),
  }
}

module.exports.getOneNote = async (event) => {
  if (!event.headers.Authorization) return { statusCode: 401 }
  if (!event.pathParameters.id || isNaN(event.pathParameters.id))
    return { statusCode: 400 }

  const id = parseInt(event.pathParameters.id)

  let user

  try {
    const res = await axios.get('https://bogdankostyuk.eu.auth0.com/userinfo', {
      headers: { Authorization: event.headers.Authorization },
    })
    user = res.data
  } catch (error) {
    return {
      statusCode: error.res.statusCode,
      body: JSON.stringify({ msg: error.res.statusMessage }),
    }
  }

  if (!user.email) return { statusCode: 400 }
  const note = await prisma.note.findUnique({
    where: { id },
    include: { owner: true },
  })

  if (!note) return { statusCode: 200, body: JSON.stringify({ data: note }) }
  if (note.owner.email !== user.email)
    return { statusCode: 200, body: JSON.stringify({ data: null }) }

  return {
    statusCode: 200,
    body: JSON.stringify({ data: note }),
  }
}

module.exports.createNote = async (event) => {
  if (!event.body) return { statusCode: 400 }

  let user

  try {
    const res = await axios.get('https://bogdankostyuk.eu.auth0.com/userinfo', {
      headers: { Authorization: event.headers.Authorization },
    })
    user = res.data
  } catch (error) {
    return {
      statusCode: error.res.statusCode,
      body: JSON.stringify({ msg: error.res.statusMessage }),
    }
  }

  let validNote

  try {
    validNote = noteCreateSchema.validateSync(event.body)
  } catch (error) {
    return { statusCode: 400 }
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

  return { statusCode: 200, body: JSON.stringify({ data: createdNote }) }
}

module.exports.updateNote = async (event) => {
  if (!event.body) return { statusCode: 400 }
  if (!event.pathParameters.id || isNaN(event.pathParameters.id))
    return { statusCode: 400 }

  const id = parseInt(event.pathParameters.id)
  let user

  try {
    const res = await axios.get('https://bogdankostyuk.eu.auth0.com/userinfo', {
      headers: { Authorization: event.headers.Authorization },
    })
    user = res.data
  } catch (error) {
    return {
      statusCode: error.res.statusCode,
      body: JSON.stringify({ msg: error.res.statusMessage }),
    }
  }

  let validNote

  try {
    validNote = noteUpdateSchema.validateSync(event.body)
  } catch (error) {
    return { statusCode: 400 }
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

  return { statusCode: 200, body: JSON.stringify({ data: updatedNote }) }
}

module.exports.deleteNote = async (event) => {
  if (!event.pathParameters.id || isNaN(event.pathParameters.id))
    return { statusCode: 400 }

  const id = parseInt(event.pathParameters.id)
  let user

  try {
    const res = await axios.get('https://bogdankostyuk.eu.auth0.com/userinfo', {
      headers: { Authorization: event.headers.Authorization },
    })
    user = res.data
  } catch (error) {
    return {
      statusCode: error.res.statusCode,
      body: JSON.stringify({ msg: error.res.statusMessage }),
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

  return { statusCode: 200, body: JSON.stringify({ data: deletedNote }) }
}
