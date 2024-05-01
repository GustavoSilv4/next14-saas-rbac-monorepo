import { auth } from "@/http/middlewares/auth"
import { prisma } from "@/lib/prisma"
import { FastifyInstance } from "fastify"
import { ZodTypeProvider } from "fastify-type-provider-zod"
import z from "zod"
import { BadRequestError } from "../_errors/bad-request-error"

export async function rejectInvite(app: FastifyInstance) {
  app
    .withTypeProvider<ZodTypeProvider>()
    .register(auth)
    .get(
      "/invites/:inviteId/reject",
      {
        schema: {
          tags: ["invites"],
          summary: "Rejects an invite",
          security: [
            {
              bearerAuth: [],
            },
          ],
          params: z.object({
            inviteId: z.string().uuid(),
          }),
          response: {
            204: z.null(),
          },
        },
      },
      async (req, reply) => {
        const userId = await req.getCurrentUserId()
        const { inviteId } = req.params

        const invite = await prisma.invite.findUnique({
          where: {
            id: inviteId,
          },
        })

        if (!invite) {
          throw new BadRequestError("Invite not found or expired.")
        }

        const user = await prisma.user.findUnique({
          where: {
            id: userId,
          },
        })

        if (!user) {
          throw new BadRequestError("User not found")
        }

        if (invite.email !== user.email) {
          throw new BadRequestError("This invite belongs another user.")
        }

        await prisma.invite.delete({
          where: {
            id: invite.id,
          },
        })

        return reply.status(204).send()
      }
    )
}
