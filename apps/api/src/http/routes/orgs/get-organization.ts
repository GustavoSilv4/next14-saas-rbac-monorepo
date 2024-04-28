import { auth } from "@/http/middlewares/auth"
import { prisma } from "@/lib/prisma"
import { FastifyInstance } from "fastify"
import { ZodTypeProvider } from "fastify-type-provider-zod"
import z from "zod"
import { BadRequestError } from "../_errors/bad-request-error"
import { createSlug } from "@/utils/create-slug"

export async function getOrganization(app: FastifyInstance) {
  app
    .withTypeProvider<ZodTypeProvider>()
    .register(auth)
    .get(
      "/organizations/:slug",
      {
        schema: {
          tags: ["organizations"],
          summary: "Get details from organization",
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
              organization: z.object({
                id: z.string(),
                name: z.string(),
                slug: z.string(),
                domain: z.string().nullable(),
                shouldAttachUsersByDomain: z.boolean(),
                avatarUrl: z.string().nullable(),
                createdAt: z.date(),
                updatedAt: z.date().nullable(),
                ownerId: z.string().uuid(),
              }),
            }),
          },
        },
      },
      async (req, reply) => {
        const { slug } = req.params
        const { organization } = await req.getUserMembership(slug)

        return {
          organization,
        }
      }
    )
}
