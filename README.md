This project was created over 3 weeks while learning Node.js/TypeScript. 
An initial version with intermediate commits is available in the old repository https://github.com/ExactD/my-node-project.

Цей проект створювався протягом 3 тижнів у процесі вивчення Node.js/TypeScript.  
Початкова версія з проміжними комітами доступна в старому репозиторії https://github.com/ExactD/my-node-project.

The project was created specifically for a user testing site, with full authentication capabilities.
Проект створений спеціально під сайт для тестування користувачів, з повною можливістю автентифікації.

To deploy the project for use, you need to download the appropriate repository, type "npm run dev" in the project console, and send requests to the server (local for now) on the port specified in the .env file.

Щоб розгорнути проект для використання потрібно скачати відповідний репозиторій, в консолі проекту прописати "npm run dev", та посилати запити на сервер(покищо локальний) на порт який вказано в .env файлі.

All functions for interacting with the server are separated into separate files index.ts, test.ts, progress.ts, the functionality and interaction with which is clear from the comments to these functions.

Всі функції для взаємодії з сервером відокремлено в окремі файли index.ts, test.ts, progress.ts, функціонал і взаємодія з якими зрозуміла по коментарях до цих функці.

В коді зроблено видачу користувачу JWT токен для зручного отримання профіля користувача