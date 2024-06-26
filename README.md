# Mnghv - Lyra Learning

This app helps you learn "atomic" things like vocabulary, formula and everything else that fits on a card.

It is built with [Nuxt3](https://v3.nuxtjs.org), [Prisma](https://www.prisma.io) and [TRPC](https://trpc.io).

[Open mohammad](https://mohammadghorayshi.ir/)

<!-- ![Preview](preview.png) -->

## Setup

Install dependencies:

```bash
npm install
```

Copy `.env.example` to `.env` and add your database connection string as well as a github client id and client secret.

Setup MySQL database:

```bash
npx prisma db push
```

Start dev server:

```bash
npm run dev
```

## TODOS

-   [x] Add learn with TRPC
-   [x] Improve auth check performance
-   [x] Add unauthorized usage option
-   [x] Sync new Github User with Anonymous User
-   [x] Add first box to fresh user
-   [x] Add smarter card relevance for new cards
-   [x] Improve card style
-   [x] Add skeleton loader
-   [x] Improve box style
-   [x] Add about page
-   [ ] Improve box overview style
-   [ ] Add card deletion
-   [ ] Add single card reset
-   [ ] Add different learning variants (timer, speech to text, ...)
-   [ ] Add learn duration diff setting
-   [ ] Add PWA support
-   [ ] Add TRPC subscriptions for cross tab updates
