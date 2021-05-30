import axios, {AxiosError} from 'axios'
import Router from 'next/router'
import { destroyCookie, parseCookies, setCookie } from 'nookies'
import { signOut } from '../contexts/AuthContext'

let cookies = parseCookies()
let isRefreshin = false
let failedRequestQueue = []

export const api = axios.create({
  baseURL: 'http://localhost:3333',
  headers: {
    Authorization: `Bearer ${cookies['nextauth.token']}`
  }
})

api.interceptors.response.use(response => {
  return response
}, (error: AxiosError) => {
  if(error.response.status === 401) {
    if(error.response.data?.code === 'token.expired') {
      cookies = parseCookies()

      const {'nextauth.refreshToken': refreshToken} = cookies
      const originalConfig = error.config

      if(!isRefreshin) {
        isRefreshin = true
        api.post('/refresh', {
          refreshToken
        }).then(response => {
          const {token} = response.data
  
          setCookie(undefined, 'nextauth.token', token, {
            maxAge: 60 * 60 * 24 * 30, // 30days
            path: '/' 
          })
  
          setCookie(undefined, 'nextauth.refreshToken', response.data.refreshToken, {
            maxAge: 60 * 60 * 24 * 30, // 30days
            path: '/' 
          })
  
          api.defaults.headers['Authorization'] = `Bearer ${token}`

          failedRequestQueue.forEach(request => request.onSuccess(token))
          failedRequestQueue = []
        }).catch(err => {
          failedRequestQueue.forEach(request => request.onFailure(err))
          failedRequestQueue = []
        }).finally(() => {
          isRefreshin = false
        })
      }

      return new Promise((resolve, reject) => {
        failedRequestQueue.push({
          onSuccess: (token: string) => {
            originalConfig.headers['Authorization'] = `Bearer ${token}`

            resolve(api(originalConfig))
          },
          onFailure: (err: AxiosError) => {
            reject(err)
          }
        })
      })
    } else {
      signOut()
    }
  }

  return Promise.reject(error)
})