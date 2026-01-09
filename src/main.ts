import { readFileSync } from 'fs';
import { NestFactory } from '@nestjs/core';
import { Logger, NestApplicationOptions, ValidationPipe } from '@nestjs/common';
import { HttpsOptions } from '@nestjs/common/interfaces/external/https-options.interface';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const httpsOptions = buildHttpsOptions(logger);
  const appOptions: NestApplicationOptions = {};
  if (httpsOptions) {
    appOptions.httpsOptions = httpsOptions;
  }
  const app = await NestFactory.create(AppModule, appOptions);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  app.enableCors({ origin: true, credentials: true });
  const port = process.env.PORT ?? 3000;
  await app.listen(port);
  const protocol = httpsOptions ? 'https' : 'http';
  logger.log(`Server listening on ${protocol}://localhost:${port}`);
}
bootstrap();

function buildHttpsOptions(logger: Logger): HttpsOptions | undefined {
  const keyPath = process.env.HTTPS_KEY_PATH;
  const certPath = process.env.HTTPS_CERT_PATH;

  if (!keyPath || !certPath) {
    return undefined;
  }

  try {
    const options: HttpsOptions = {
      key: readFileSync(keyPath),
      cert: readFileSync(certPath),
    };

    if (process.env.HTTPS_CA_PATH) {
      options.ca = readFileSync(process.env.HTTPS_CA_PATH);
    }

    logger.log('HTTPS enabled using certificate files from environment variables');
    return options;
  } catch (error) {
    const err = error as Error;
    logger.error(`Failed to load HTTPS certificates: ${err.message}`, err.stack);
    throw error;
  }
}
