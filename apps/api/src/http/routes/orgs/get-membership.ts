import { auth } from "@/http/middlewares/auth"
import { roleSchema } from "@saas/auth/src/roles"
import { FastifyInstance } from "fastify"
import { ZodTypeProvider } from "fastify-type-provider-zod"
import z from "zod"

export async function getMembership(app: FastifyInstance) {
  app
    .withTypeProvider<ZodTypeProvider>()
    .register(auth)
    .get(
      "/organizations/:slug/membership",
      {
        schema: {
          tags: ["organizations"],
          summary: "Get user membership on organization",
          security: [
            {
              bearerAuth: [],
            },
          ],
          params: z.object({
            slug: z.string(),
          }),
          response: {
            200: z.object({
              membership: z.object({
                id: z.string().uuid(),
                role: roleSchema,
                organizationId: z.string().uuid(),
              }),
            }),
          },
        },
      },
      async (req, reply) => {
        const { slug } = req.params

        const { membership } = await req.getUserMembership(slug)

        return {
          membership: {
            id: membership.id,
            role: membership.role,
            organizationId: membership.organizationId,
          },
        }
      }
    )
}
