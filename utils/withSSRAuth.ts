import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from "next";
import { destroyCookie, parseCookies } from "nookies";
import { AuthTokenError } from "../src/services/errors/AuthTokenError";
import decode from 'jwt-decode'
import { ValidadeUserPermissions } from "./validadeUserPermissions";

type WithSSRAuthOptionsProps ={
  permissions?: string[];
  roles?: string[];
}

export function WithSSRAuth<p>(fn: GetServerSideProps<p>, options?: WithSSRAuthOptionsProps) {
  return async (ctx: GetServerSidePropsContext): Promise<GetServerSidePropsResult<p>> => {
    const cookies = parseCookies(ctx)
    const token = cookies['nextauth.token']
    if (!token) {
      return {
        redirect: {
          destination: '/',
          permanent: false,
        }
      }
    }

    if(options) {
      const user = decode<{permissions: string[], roles: string[]}>(token)
      const { permissions, roles } = options
      const userHasValidPermissions = ValidadeUserPermissions({
        user,
        permissions,
        roles
      })

      if(!userHasValidPermissions) {
        return {
          redirect: {
            destination: '/dashboard',
            permanent: false
          }
        }
      }
    }

    try {
      return await fn(ctx)

    } catch (err) {
      if(err instanceof AuthTokenError) {
        destroyCookie(ctx, 'nextauth.token')
        destroyCookie(ctx, 'nextauth.refreshToken')
  
        return {
          redirect: {
            destination: '/',
            permanent: false
          }
        }
      }
    }
  }
}