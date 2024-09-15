import { useEnv } from '@directus/env';

import { InvalidCredentialsError, InvalidPayloadError } from '@directus/errors';
import type { Accountability } from '@directus/types';
import { Router } from 'express';
import { default as BaseJoi } from 'joi';
import { performance } from 'perf_hooks';
import { REFRESH_COOKIE_OPTIONS, SESSION_COOKIE_OPTIONS } from '../../constants.js';
import { respond } from '../../middleware/respond.js';
import { createDefaultAccountability } from '../../permissions/utils/create-default-accountability.js';
import { AuthenticationService } from '../../services/authentication.js';
import type { AuthenticationMode, User } from '../../types/index.js';
import asyncHandler from '../../utils/async-handler.js';
import { getIPFromReq } from '../../utils/get-ip-from-req.js';
import { stall } from '../../utils/stall.js';
import { AuthDriver } from '../auth.js';
import JoiPhoneNumber from 'joi-phone-number'
import twilio from "twilio"
import { getAuthProvider } from '../../auth.js';

const env = useEnv()

const client = twilio(env['TWILIO_ACCOUNT_SID'] as string, env['TWILIO_AUTH_TOKEN'] as string)

const Joi = BaseJoi.extend(JoiPhoneNumber);

export class TwilioAuthDriver extends AuthDriver {

	async getUserID(payload: Record<string, any>): Promise<string> {
		if (!payload['phone']) {
			throw new InvalidCredentialsError();
		}

		const user = await this.knex
			.select('id')
			.from('directus_users')
			.whereRaw('LOWER(??) = ?', ['phone', payload['phone'].toLowerCase()])
			.first();

		if (!user) {
			throw new InvalidCredentialsError();
		}

		return user.id;
	}

	async verify(user: User, code: string): Promise<void> {
		if (!user.phone) {
			throw new InvalidCredentialsError();
		}
		const verificationCheck = await client.verify.v2
			.services(env['TWILIO_SERVICE'] as string)
			.verificationChecks.create({
				code,
				to: user.phone,
			});

		if (verificationCheck.status !== 'approved') {
			throw new InvalidCredentialsError();
		}
	}

	async createVerification(payload: Record<string, any>): Promise<void> {
		await client.verify.v2
			.services(env['TWILIO_SERVICE'] as string)
			.verifications.create({
				channel: "sms",
				to: payload['phone'],
			});
	}

	override async login(user: User, payload: Record<string, any>): Promise<void> {
		await this.verify(user, payload['code']);
	}
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
		code: Joi.string(),
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
