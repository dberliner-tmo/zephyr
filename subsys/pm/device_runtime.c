/*
 * Copyright (c) 2018 Intel Corporation.
 * Copyright (c) 2021 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

<<<<<<< HEAD
#include <sys/__assert.h>
#include <pm/device_runtime.h>
=======
#include <pm/device.h>
#include <pm/device_runtime.h>
#include <sys/__assert.h>
>>>>>>> tmo-main

#include <logging/log.h>
LOG_MODULE_DECLARE(pm_device, CONFIG_PM_DEVICE_LOG_LEVEL);

/**
 * @brief Suspend a device
 *
 * @note Asynchronous operations are not supported when in pre-kernel mode. In
 * this case, the async flag will be always forced to be false, and so the
 * the function will be blocking.
 *
 * @funcprops \pre_kernel_ok
 *
 * @param dev Device instance.
 * @param async Perform operation asynchronously.
 *
 * @retval 0 If device has been suspended or queued for suspend.
 * @retval -EALREADY If device is already suspended (can only happen if get/put
 * calls are unbalanced).
 * @retval -errno Other negative errno, result of the action callback.
 */
static int runtime_suspend(const struct device *dev, bool async)
{
	int ret = 0;
	struct pm_device *pm = dev->pm;

	if (k_is_pre_kernel()) {
		async = false;
	} else {
		(void)k_mutex_lock(&pm->lock, K_FOREVER);
	}

<<<<<<< HEAD
	/* Clear transitioning flags */
	atomic_clear_bit(&pm->flags, PM_DEVICE_FLAG_TRANSITIONING);

	switch (pm->state) {
	case PM_DEVICE_STATE_ACTIVE:
		if ((pm->usage == 0) && pm->enable) {
			ret = pm_device_state_set(dev, PM_DEVICE_STATE_SUSPENDED);
		}
		break;
	case PM_DEVICE_STATE_SUSPENDED:
		if ((pm->usage > 0) || !pm->enable) {
			ret = pm_device_state_set(dev, PM_DEVICE_STATE_ACTIVE);
=======
	if ((pm->flags & BIT(PM_DEVICE_FLAG_RUNTIME_ENABLED)) == 0U) {
		goto unlock;
	}

	if (pm->usage == 0U) {
		LOG_WRN("Unbalanced suspend");
		ret = -EALREADY;
		goto unlock;
	}

	pm->usage--;
	if (pm->usage > 0U) {
		goto unlock;
	}

	if (async && !k_is_pre_kernel()) {
		/* queue suspend */
		pm->state = PM_DEVICE_STATE_SUSPENDING;
		(void)k_work_schedule(&pm->work, K_NO_WAIT);
	} else {
		/* suspend now */
		ret = pm->action_cb(pm->dev, PM_DEVICE_ACTION_SUSPEND);
		if (ret < 0) {
			pm->usage++;
			goto unlock;
>>>>>>> tmo-main
		}

		pm->state = PM_DEVICE_STATE_SUSPENDED;
	}

unlock:
	if (!k_is_pre_kernel()) {
		k_mutex_unlock(&pm->lock);
	}

<<<<<<< HEAD
	/*
	 * This function returns the number of woken threads on success. There
	 * is nothing we can do with this information. Just ignoring it.
	 */
	(void)k_condvar_broadcast(&pm->condvar);
=======
	return ret;
>>>>>>> tmo-main
}

static void runtime_suspend_work(struct k_work *work)
{
	int ret;
	struct pm_device *pm = CONTAINER_OF(work, struct pm_device, work);

	ret = pm->action_cb(pm->dev, PM_DEVICE_ACTION_SUSPEND);

	(void)k_mutex_lock(&pm->lock, K_FOREVER);
	if (ret == 0) {
		pm->state = PM_DEVICE_STATE_SUSPENDED;
	}
	k_condvar_broadcast(&pm->condvar);
	k_mutex_unlock(&pm->lock);

	__ASSERT(ret == 0, "Could not suspend device (%d)", ret);
}

int pm_device_runtime_get(const struct device *dev)
{
	int ret = 0;
	struct pm_device *pm = dev->pm;

	SYS_PORT_TRACING_FUNC_ENTER(pm, device_runtime_get, dev);

<<<<<<< HEAD
	__ASSERT((state == PM_DEVICE_STATE_ACTIVE) ||
			(state == PM_DEVICE_STATE_SUSPENDED),
			"Invalid device PM state requested");

	if (k_is_pre_kernel()) {
		if (state == PM_DEVICE_STATE_ACTIVE) {
			pm->usage++;
		} else {
			pm->usage--;
		}

		/* If we are being called before the kernel was initialized
		 * we can assume that the system took care of initialized
		 * devices properly. It means that all dependencies were
		 * satisfied and this call just incremented the reference count
		 * for this device.
		 */

		/* Unfortunately this is not what is happening yet. There are
		 * cases, for example, like the pinmux being initialized before
		 * the gpio. Lets just power on/off the device.
		 */
		if (pm->usage == 1) {
			(void)pm_device_state_set(dev, PM_DEVICE_STATE_ACTIVE);
		} else if (pm->usage == 0) {
			(void)pm_device_state_set(dev, PM_DEVICE_STATE_SUSPENDED);
		}
		goto out;
	}

	(void)k_mutex_lock(&pm->lock, K_FOREVER);

	if (!pm->enable) {
		ret = -ENOTSUP;
		goto out_unlock;
	}

	if (state == PM_DEVICE_STATE_ACTIVE) {
		pm->usage++;
		if (pm->usage > 1) {
			goto out_unlock;
		}
	} else {
		/* Check if it is already 0 to avoid an underflow */
		if (pm->usage == 0) {
			goto out_unlock;
		}

		pm->usage--;
		if (pm->usage > 0) {
			goto out_unlock;
		}
	}


	/* Return in case of Async request */
	if (pm_flags & PM_DEVICE_ASYNC) {
		atomic_set_bit(&pm->flags, PM_DEVICE_FLAG_TRANSITIONING);
		(void)k_work_schedule(&pm->work, K_NO_WAIT);
		goto out_unlock;
	}

	while ((k_work_delayable_is_pending(&pm->work)) ||
	       atomic_test_bit(&pm->flags, PM_DEVICE_FLAG_TRANSITIONING)) {
		ret = k_condvar_wait(&pm->condvar, &pm->lock,
			       K_FOREVER);
		if (ret != 0) {
			break;
		}
	}

	pm_device_runtime_state_set(pm);

	/*
	 * pm->state was set in pm_device_runtime_state_set(). As the
	 * device may not have been properly changed to the state or
	 * another thread we check it here before returning.
	 */
	ret = state == pm->state ? 0 : -EIO;

out_unlock:
	(void)k_mutex_unlock(&pm->lock);
out:
	SYS_PORT_TRACING_FUNC_EXIT(pm, device_request, dev, ret);
=======
	if (!k_is_pre_kernel()) {
		(void)k_mutex_lock(&pm->lock, K_FOREVER);
	}

	if ((pm->flags & BIT(PM_DEVICE_FLAG_RUNTIME_ENABLED)) == 0U) {
		goto unlock;
	}

	pm->usage++;

	if (!k_is_pre_kernel()) {
		/* wait until possible async suspend is completed */
		while (pm->state == PM_DEVICE_STATE_SUSPENDING) {
			(void)k_condvar_wait(&pm->condvar, &pm->lock, K_FOREVER);
		}
	}

	if (pm->usage > 1U) {
		goto unlock;
	}

	ret = pm->action_cb(pm->dev, PM_DEVICE_ACTION_RESUME);
	if (ret < 0) {
		pm->usage--;
		goto unlock;
	}

	pm->state = PM_DEVICE_STATE_ACTIVE;

unlock:
	if (!k_is_pre_kernel()) {
		k_mutex_unlock(&pm->lock);
	}

	SYS_PORT_TRACING_FUNC_EXIT(pm, device_runtime_get, dev, ret);

>>>>>>> tmo-main
	return ret;
}

int pm_device_runtime_put(const struct device *dev)
{
	int ret;

	SYS_PORT_TRACING_FUNC_ENTER(pm, device_runtime_put, dev);
	ret = runtime_suspend(dev, false);
	SYS_PORT_TRACING_FUNC_EXIT(pm, device_runtime_put, dev, ret);

	return ret;
}

int pm_device_runtime_put_async(const struct device *dev)
{
	int ret;

	SYS_PORT_TRACING_FUNC_ENTER(pm, device_runtime_put_async, dev);
	ret = runtime_suspend(dev, true);
	SYS_PORT_TRACING_FUNC_EXIT(pm, device_runtime_put_async, dev, ret);

	return ret;
}

int pm_device_runtime_enable(const struct device *dev)
{
<<<<<<< HEAD
	struct pm_device *pm = dev->pm;

	SYS_PORT_TRACING_FUNC_ENTER(pm, device_enable, dev);
	if (k_is_pre_kernel()) {
		pm->dev = dev;
		if (pm->action_cb != NULL) {
			pm->enable = true;
			pm->state = PM_DEVICE_STATE_SUSPENDED;
			k_work_init_delayable(&pm->work, pm_work_handler);
		}
		goto out;
	}

	(void)k_mutex_lock(&pm->lock, K_FOREVER);
	if (pm->action_cb == NULL) {
		pm->enable = false;
		goto out_unlock;
	}

	pm->enable = true;

	/* During the driver init, device can set the
	 * PM state accordingly. For later cases we need
	 * to check the usage and set the device PM state.
	 */
	if (!pm->dev) {
		pm->dev = dev;
		pm->state = PM_DEVICE_STATE_SUSPENDED;
		k_work_init_delayable(&pm->work, pm_work_handler);
	} else {
		k_work_schedule(&pm->work, K_NO_WAIT);
	}

out_unlock:
	(void)k_mutex_unlock(&pm->lock);
out:
	SYS_PORT_TRACING_FUNC_EXIT(pm, device_enable, dev);
}

void pm_device_disable(const struct device *dev)
{
	struct pm_device *pm = dev->pm;

	SYS_PORT_TRACING_FUNC_ENTER(pm, device_disable, dev);
	__ASSERT(k_is_pre_kernel() == false, "Device should not be disabled "
		 "before kernel is initialized");

	(void)k_mutex_lock(&pm->lock, K_FOREVER);
	if (pm->enable) {
		pm->enable = false;
		/* Bring up the device before disabling the Idle PM */
		k_work_schedule(&pm->work, K_NO_WAIT);
	}
	(void)k_mutex_unlock(&pm->lock);
	SYS_PORT_TRACING_FUNC_EXIT(pm, device_disable, dev);
=======
	int ret = 0;
	struct pm_device *pm = dev->pm;

	SYS_PORT_TRACING_FUNC_ENTER(pm, device_runtime_enable, dev);

	if (pm_device_state_is_locked(dev)) {
		ret = -EPERM;
		goto end;
	}

	if (!k_is_pre_kernel()) {
		(void)k_mutex_lock(&pm->lock, K_FOREVER);
	}

	if ((pm->flags & BIT(PM_DEVICE_FLAG_RUNTIME_ENABLED)) != 0U) {
		goto unlock;
	}

	/* lazy init of PM fields */
	if (pm->dev == NULL) {
		pm->dev = dev;
		k_work_init_delayable(&pm->work, runtime_suspend_work);
	}

	if (pm->state == PM_DEVICE_STATE_ACTIVE) {
		ret = pm->action_cb(pm->dev, PM_DEVICE_ACTION_SUSPEND);
		if (ret < 0) {
			goto unlock;
		}
	}

	pm->state = PM_DEVICE_STATE_SUSPENDED;
	pm->usage = 0U;

	atomic_set_bit(&pm->flags, PM_DEVICE_FLAG_RUNTIME_ENABLED);

unlock:
	if (!k_is_pre_kernel()) {
		k_mutex_unlock(&pm->lock);
	}

end:
	SYS_PORT_TRACING_FUNC_EXIT(pm, device_runtime_enable, dev, ret);
	return ret;
>>>>>>> tmo-main
}

int pm_device_runtime_disable(const struct device *dev)
{
	int ret = 0;
	struct pm_device *pm = dev->pm;
<<<<<<< HEAD

	k_mutex_lock(&pm->lock, K_FOREVER);
	while ((k_work_delayable_is_pending(&pm->work)) ||
	       atomic_test_bit(&pm->flags, PM_DEVICE_FLAG_TRANSITIONING)) {
		ret = k_condvar_wait(&pm->condvar, &pm->lock,
			       timeout);
		if (ret != 0) {
			break;
		}
	}
	k_mutex_unlock(&pm->lock);
=======

	SYS_PORT_TRACING_FUNC_ENTER(pm, device_runtime_disable, dev);

	if (!k_is_pre_kernel()) {
		(void)k_mutex_lock(&pm->lock, K_FOREVER);
	}

	if ((pm->flags & BIT(PM_DEVICE_FLAG_RUNTIME_ENABLED)) == 0U) {
		goto unlock;
	}

	/* wait until possible async suspend is completed */
	if (!k_is_pre_kernel()) {
		while (pm->state == PM_DEVICE_STATE_SUSPENDING) {
			(void)k_condvar_wait(&pm->condvar, &pm->lock,
					     K_FOREVER);
		}
	}

	/* wake up the device if suspended */
	if (pm->state == PM_DEVICE_STATE_SUSPENDED) {
		ret = pm->action_cb(pm->dev, PM_DEVICE_ACTION_RESUME);
		if (ret < 0) {
			goto unlock;
		}

		pm->state = PM_DEVICE_STATE_ACTIVE;
	}

	atomic_clear_bit(&pm->flags, PM_DEVICE_FLAG_RUNTIME_ENABLED);

unlock:
	if (!k_is_pre_kernel()) {
		k_mutex_unlock(&pm->lock);
	}

	SYS_PORT_TRACING_FUNC_EXIT(pm, device_runtime_disable, dev, ret);
>>>>>>> tmo-main

	return ret;
}

bool pm_device_runtime_is_enabled(const struct device *dev)
{
	struct pm_device *pm = dev->pm;

	return atomic_test_bit(&pm->flags, PM_DEVICE_FLAG_RUNTIME_ENABLED);
}
