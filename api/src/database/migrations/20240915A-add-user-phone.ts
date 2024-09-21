import type { Knex } from 'knex';
import { getHelpers } from '../helpers/index.js';

export async function up(knex: Knex): Promise<void> {
	await knex.schema.alterTable('directus_users', (table) => {
		table.string('phone', 20).nullable();
	});
}

export async function down(knex: Knex): Promise<void> {
	return knex.schema.alterTable('directus_users', (table) => {
    table.dropColumn('phone');
  });
}
