import { prisma } from "@/lib/prisma";
import { FastifyInstance } from "fastify";
import { ZodTypeProvider } from "fastify-type-provider-zod";
import z from "zod";

export async function authenticateWithGithub(app:FastifyInstance){
  app.withTypeProvider<ZodTypeProvider>().post('/sessions/github', {
    schema: {
      tags: ['auth'],
      summary: 'Authenticate with Github',
      body: z.object({
        code: z.string(),
      }),
      response: {
        201: z.object({
          token: z.string()
        })
      }
    }
  }, async (req, reply) => {
    const {code} = req.body

    const githubOAuthURL = new URL('https://github.com/login/oauth/access_token')

    githubOAuthURL.searchParams.set('client_id', '7f9ff3e386b51129d7e5')
    githubOAuthURL.searchParams.set('client_secret', '8ca554b09137389cf73b2b9b6c06ba34df41b5ab')
    githubOAuthURL.searchParams.set('redirect_uri', 'http://localhost:3000/api/auth/callback')
    githubOAuthURL.searchParams.set('code', code)

    const githubAccessTokenResponse = await fetch(githubOAuthURL, {
      method: 'POST',
      headers:{
        Accept: 'application/json'
      }
    })

    const githubAccessTokenData = await githubAccessTokenResponse.json()

    const { access_token: githubAccessToken } = z.object({
      access_token: z.string(),
      token_type: z.literal('bearer'),
      scope: z.string()
    }).parse(githubAccessTokenData)

    const githubUserResponse = await fetch('https://api.github.com/user', {
      headers:{
        Authorization: 'Bearer ' + githubAccessToken
      }
    })

    const githubUserData = await githubUserResponse.json()

    const {id: githubId, name, email, avatar_url: avatarUrl} = z.object({
      id: z.number().int(),
      avatar_url: z.string().url(),
      name: z.string().nullable(),
      email: z.string().email().nullable()
    }).parse(githubUserData)

    if(email === null){
      throw new Error('Your Github account must have an email address to authenticate.')
    }

    let user = await prisma.user.findUnique({
      where: {
        email
      }
    })

    if(!user){
      user = await prisma.user.create({
        data: {
          email,
          name,
          avatarUrl,
        }
      })
    }

    let account = await prisma.account.findUnique({
      where: {
        provider_userId: {
          provider: 'GITHUB',
          userId: user.id
        }
      }
    })

    if(!account){
      account = await prisma.account.create({
        data: {
          provicerAccountId: githubId.toString(),
          provider: 'GITHUB',
          userId: user.id
        }
      })
    }

    const token = await reply.jwtSign({
      sub: user.id
    }, {
      sign: {
        expiresIn: '7d'
      }
    })

    return reply.status(201).send({token})
  })
}