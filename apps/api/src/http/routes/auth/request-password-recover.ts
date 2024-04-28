import { prisma } from "@/lib/prisma";
import { FastifyInstance } from "fastify";
import { ZodTypeProvider } from "fastify-type-provider-zod";
import z from "zod";
import { BadRequestError } from "../_errors/bad-request-error";
import { auth } from "@/http/middlewares/auth";

export async function requestPasswordRecover(app:FastifyInstance){
  app.withTypeProvider<ZodTypeProvider>().post('/password/recover', {
    schema: {
      tags: ['auth'],
      summary: 'Get authenticated user profile',
      body: z.object({
        email: z.string().email()
      }),
      response: {
        201: z.null()
      }
    }
  }, async (req, reply) => {
    const {email} = req.body

    const userFromEmail = await prisma.user.findUnique({
      where: {email}
    })

    if(!userFromEmail){
      return reply.status(201).send()
    }

   const {id: code} = await prisma.token.create({
      data: {
        type: 'PASSWORD_RECOVER',
        userId: userFromEmail.id
      }
    })

    // Send e-mail with password recover link

    console.log('Recover password token: ', code)

    return reply.status(201).send()
  })
}