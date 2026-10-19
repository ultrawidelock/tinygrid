/* SPDX-License-Identifier: Apache-2.0 */
/* tinygrid on Zephyr: the lock every caller outside the stack's thread takes. */
#pragma once

/** Serialise a call into tg.h from any thread but tinygrid's own. Recursive. */
void tg_zephyr_lock(void);

/** Release it, and let the stack's thread recompute its next deadline. */
void tg_zephyr_unlock(void);

/** Called with the lock held whenever tg_plat_changed() fires. Weak; a user overrides it. */
void tg_zephyr_changed(void);
