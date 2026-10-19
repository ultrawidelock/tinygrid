/* SPDX-License-Identifier: Apache-2.0 */
/* Host port: a tinygrid node on OpenThread's simulated radio. */
#pragma once

/** Join the simulation as @p node_id; persisted records go under @p dir. */
int tg_host_init(int node_id, const char *dir);

/**
 * Run the stack until something happens: a frame, a deadline, or @p extra_fd
 * becoming readable (then returns 1). Returns 0 otherwise, < 0 on error.
 */
int tg_host_step(int extra_fd);
