import { auth } from "@/http/middlewares/auth"
import { prisma } from "@/lib/prisma"
import { FastifyInstance } from "fastify"
import { ZodTypeProvider } from "fastify-type-provider-zod"
import z from "zod"
import { BadRequestError } from "../_errors/bad-request-error"
import { getUserPermissions } from "@/utils/get-user-permissions"
import { UnauthorizedError } from "../_errors/unauthorized-error"
import { projectSchema } from "@saas/auth/src/models/project"

export async function updateProject(app: FastifyInstance) {
  app
    .withTypeProvider<ZodTypeProvider>()
    .register(auth)
    .put(
      "/organizations/:slug/projects/:projectId",
      {
        schema: {
          tags: ["projects"],
          summary: "Update a project",
          security: [
            {
              bearerAuth: [],
            },
          ],
          body: z.object({
            name: z.string(),
            description: z.string(),
          }),
          params: z.object({
            slug: z.string(),
            projectId: z.string().uuid(),
          }),
          response: {
            204: z.null(),
          },
        },
      },
      async (req, reply) => {
        const { slug, projectId } = req.params
        const userId = await req.getCurrentUserId()
        const { membership, organization } = await req.getUserMembership(slug)

        const project = await prisma.project.findUnique({
          where: {
            id: projectId,
            organizationId: organization.id,
          },
        })

        if (!project) {
          throw new BadRequestError("Project not found")
        }

        const { cannot } = getUserPermissions(userId, membership.role)
        const authProject = projectSchema.parse(project)

        if (cannot("update", authProject)) {
          throw new UnauthorizedError(
            "You are not allowed to update this projects."
          )
        }

        const { description, name } = req.body

        await prisma.project.update({
          where: {
            id: projectId,
          },
          data: {
            name,
            description,
          },
        })

        return reply.status(204).send()
      }
    )
}
