import { auth } from "@/http/middlewares/auth"
import { prisma } from "@/lib/prisma"
import { FastifyInstance } from "fastify"
import { ZodTypeProvider } from "fastify-type-provider-zod"
import z from "zod"
import { getUserPermissions } from "@/utils/get-user-permissions"
import { UnauthorizedError } from "../_errors/unauthorized-error"
import { roleSchema } from "@saas/auth/src/roles"
import { BadRequestError } from "../_errors/bad-request-error"

export async function removeMember(app: FastifyInstance) {
  app
    .withTypeProvider<ZodTypeProvider>()
    .register(auth)
    .delete(
      "/organizations/:slug/members/:memberId",
      {
        schema: {
          tags: ["members"],
          summary: "Remove a member from the organization",
          security: [
            {
              bearerAuth: [],
            },
          ],
          params: z.object({
            slug: z.string(),
            memberId: z.string().uuid(),
          }),
          response: {
            204: z.null(),
          },
        },
      },
      async (req, reply) => {
        const { slug, memberId } = req.params
        const userId = await req.getCurrentUserId()
        const { membership, organization } = await req.getUserMembership(slug)

        const { cannot } = getUserPermissions(userId, membership.role)

        if (cannot("delete", "User")) {
          throw new UnauthorizedError(
            "You are not allowed to update this member."
          )
        }
        const member = await prisma.member.findUnique({
          where: {
            id: memberId,
            organizationId: organization.id,
          },
        })

        if (!member) {
          throw new BadRequestError("Member not found in membership")
        }

        await prisma.member.delete({
          where: {
            id: memberId,
            organizationId: organization.id,
          },
        })

        return reply.status(200).send()
      }
    )
}
