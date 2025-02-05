import { useEnv } from '@directus/env';

import { ErrorCode, isDirectusError, InvalidCredentialsError, InvalidPayloadError, InvalidProviderError, InvalidProviderConfigError, ServiceUnavailableError } from '@directus/errors';
import type { Accountability } from '@directus/types';
import { Router } from 'express';
import { default as BaseJoi } from 'joi';
import { performance } from 'perf_hooks';
import { REFRESH_COOKIE_OPTIONS, SESSION_COOKIE_OPTIONS } from '../../constants.js';
import { respond } from '../../middleware/respond.js';
import { createDefaultAccountability } from '../../permissions/utils/create-default-accountability.js';
import { AuthenticationService } from '../../services/authentication.js';
import type { AuthenticationMode } from '../../types/index.js';
import asyncHandler from '../../utils/async-handler.js';
import { getIPFromReq } from '../../utils/get-ip-from-req.js';
import { stall } from '../../utils/stall.js';
import JoiPhoneNumber from 'joi-phone-number'
import Twilio from "twilio"
import { getAuthProvider } from '../../auth.js';
import { useLogger } from '../../logger/index.js';
import { UsersService } from '../../services/users.js';
import emitter from '../../emitter.js';
import getDatabase from '../../database/index.js';
import type { AuthDriverOptions } from '../../types/index.js';
import { LocalAuthDriver } from './local.js';

const Joi = BaseJoi.extend(JoiPhoneNumber);

export class TwilioAuthDriver extends LocalAuthDriver {
	client: Twilio.Twilio;
	config: Record<string, any>;
	usersService: UsersService;

	constructor(options: AuthDriverOptions, config: Record<string, any>) {
		super(options, config);

		const logger = useLogger()

		const { twilioAccountSid, twilioAuthToken, twilioService, ...additionalConfig } = config

		if (!twilioAccountSid || !twilioAuthToken || !twilioService || !additionalConfig['provider']) {
			logger.error('Invalid provider config');
			throw new InvalidProviderConfigError({ provider: additionalConfig['provider'] });
		}

		this.client = new Twilio.Twilio(twilioAccountSid, twilioAuthToken)
		this.config = config
		this.usersService = new UsersService({ knex: this.knex, schema: this.schema });
	}

	private async fetchUserId(phone: string): Promise<string | undefined> {
		const user = await this.knex
			.select('id')
			.from('directus_users')
			.whereRaw('?? = ?', ['phone', phone])
			.first();

		return user?.id;
	}

	override async getUserID(payload: Record<string, any>): Promise<string> {
		const logger = useLogger()
		if (!payload['phone']) {
			throw new InvalidCredentialsError();
		}

		await this.verifyCode(payload['phone'], payload['code']);

		let userId = await this.fetchUserId(payload['phone'])

		if (!userId) {
			const { provider } = this.config

			const userPayload = {
				provider,
				phone: payload['phone'],
				role: this.config['defaultRoleId'],
			};

			const updatedUserPayload = await emitter.emitFilter(
				`auth.create`,
				userPayload,
				{
					phone: payload['phone'],
					provider: this.config['provider'],
				},
				{ database: getDatabase(), schema: this.schema, accountability: null },
			);

			try {
				await this.usersService.createOne(updatedUserPayload);
			} catch (e) {
				if (isDirectusError(e, ErrorCode.RecordNotUnique)) {
					logger.warn(e, '[Twilio] Failed to register user. User not unique');
					throw new InvalidProviderError();
				}

				throw e;
			}
		}

		userId = await this.fetchUserId(payload['phone'])

		if (!userId) {
			logger.warn('[Twilio] Failed to register user');
			throw new InvalidProviderError()
		}

		return userId;
	}

	async verifyCode(phone: string, code: string): Promise<void> {
		const logger = useLogger()
		let verificationCheck
		try {
			verificationCheck = await this.client.verify.v2
				.services(this.config['twilioService'] as string)
				.verificationChecks.create({
					code,
					to: phone,
				});
		} catch (e: any) {
			if (e.code === 20404) {
				logger.warn(e, '[Twilio] Verification does not exist')
				throw new InvalidCredentialsError();
			} else {
				logger.warn(e, '[Twilio] Unkown error')
				throw new ServiceUnavailableError({
					service: 'twilio',
					reason: `Service returned unexpected response: ${e.message}`,
				});
			}
		}

		if (verificationCheck?.status !== 'approved') {
			throw new InvalidCredentialsError();
		}
	}

	async createVerification(payload: Record<string, any>): Promise<void> {
		const logger = useLogger()
		try {
			await this.client.verify.v2
				.services(this.config['twilioService'] as string)
				.verifications.create({
					channel: "sms",
					to: payload['phone'],
				});
		} catch (e: any) {
			logger.warn(e, '[Twilio] Unkown error')
			throw new ServiceUnavailableError({
				service: 'twilio',
				reason: `Service returned unexpected response: ${e.message}`,
			});
		}
	}

	override async login(): Promise<void> {}
}

export function createTwilioAuthRouter(providerName: string): Router {
	const env = useEnv();

	const router = Router();

	const userLoginSchema = Joi.object({
		mode: Joi.string().valid('cookie', 'json', 'session'),
		phone: Joi.string().phoneNumber({
			defaultCountry: 'US',
			format: 'national'
		}).required(),
		code: Joi.string().required(),
	}).unknown();

	const verifySchema = Joi.object({
		phone: Joi.string().phoneNumber({
			defaultCountry: 'US',
			format: 'national'
		}).required()
	}).unknown();

	router.post(
		'/verify',
		asyncHandler(async (req, _, next) => {
			const provider = getAuthProvider(providerName) as TwilioAuthDriver;
			const { error } = verifySchema.validate(req.body);
			if (error) {
				throw new InvalidPayloadError({ reason: error.message });
			}
			await provider.createVerification(req.body)
			return next()
		}),
		respond
	)

	router.post(
		'/',
		asyncHandler(async (req, res, next) => {
			const STALL_TIME = env['LOGIN_STALL_TIME'] as number;
			const timeStart = performance.now();

			const accountability: Accountability = createDefaultAccountability({
				ip: getIPFromReq(req),
			});

			const userAgent = req.get('user-agent')?.substring(0, 1024);
			if (userAgent) accountability.userAgent = userAgent;

			const origin = req.get('origin');
			if (origin) accountability.origin = origin;

			const authenticationService = new AuthenticationService({
				accountability: accountability,
				schema: req.schema,
			});

			const { error } = userLoginSchema.validate(req.body);

			if (error) {
				await stall(STALL_TIME, timeStart);
				throw new InvalidPayloadError({ reason: error.message });
			}

			const mode: AuthenticationMode = req.body.mode ?? 'json';

			const { accessToken, refreshToken, expires } = await authenticationService.login(providerName, req.body, {
				session: mode === 'session',
				otp: req.body?.otp,
			});

			const payload = { expires } as { expires: number; access_token?: string; refresh_token?: string };

			if (mode === 'json') {
				payload.refresh_token = refreshToken;
				payload.access_token = accessToken;
			}

			if (mode === 'cookie') {
				res.cookie(env['REFRESH_TOKEN_COOKIE_NAME'] as string, refreshToken, REFRESH_COOKIE_OPTIONS);
				payload.access_token = accessToken;
			}

			if (mode === 'session') {
				res.cookie(env['SESSION_COOKIE_NAME'] as string, accessToken, SESSION_COOKIE_OPTIONS);
			}

			res.locals['payload'] = { data: payload };

			return next();
		}),
		respond,
	);

	return router;
}
