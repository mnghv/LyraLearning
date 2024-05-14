import { createTRPCHandler } from 'trpc-nuxt/api'
import * as functions from '/Users/m.nghv/Sites/localhost/LyraLearning/server/trpc'

export default createTRPCHandler({
  ...functions,
  endpoint: '/trpc'
})