// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * KUnit tests for the tty core's cdev-slot lifetime.
 *
 * Upstream 6645856f0df3 clears driver->cdevs[index] when tty_cdev_add()
 * fails, because the failed cdev_add() path has already dropped the cdev
 * reference.  cdev_del() has no NULL guard, so the clearing is only safe when
 * every later user of the slot skips a cleared one: tty_unregister_device()
 * and the driver destruct loop must both tolerate NULL slots.  These cases pin
 * that, plus the normal path where a real cdev is still released.
 */

#include <kunit/test.h>

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>

static void tty_unregister_device_skips_a_cleared_slot(struct kunit *test)
{
	struct tty_driver *driver;

	driver = tty_alloc_driver(1, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, driver);

	/* The shape left behind by a failed tty_cdev_add(). */
	driver->cdevs[0] = NULL;

	tty_unregister_device(driver, 0);

	KUNIT_EXPECT_NULL(test, driver->cdevs[0]);
	tty_driver_kref_put(driver);
}

static void tty_unregister_device_releases_a_real_cdev(struct kunit *test)
{
	struct tty_driver *driver;
	dev_t dev = 0;
	int err;

	driver = tty_alloc_driver(1, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, driver);

	err = alloc_chrdev_region(&dev, 0, 1, "tty_kunit");
	KUNIT_ASSERT_EQ(test, err, 0);

	driver->cdevs[0] = cdev_alloc();
	KUNIT_ASSERT_NOT_NULL(test, driver->cdevs[0]);
	KUNIT_ASSERT_EQ(test, cdev_add(driver->cdevs[0], dev, 1), 0);

	tty_unregister_device(driver, 0);

	KUNIT_EXPECT_NULL(test, driver->cdevs[0]);
	unregister_chrdev_region(dev, 1);
	tty_driver_kref_put(driver);
}

static void tty_driver_release_survives_cleared_slots(struct kunit *test)
{
	struct tty_driver *driver;

	/*
	 * TTY_DRIVER_INSTALLED routes release through the per-line
	 * tty_unregister_device() loop and the dynamic-alloc cdev_del(); both
	 * meet a cleared slot here.
	 */
	driver = tty_alloc_driver(1, TTY_DRIVER_INSTALLED | TTY_DRIVER_DYNAMIC_ALLOC);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, driver);

	driver->cdevs[0] = NULL;

	tty_driver_kref_put(driver);
	KUNIT_SUCCEED(test);
}

static struct kunit_case tty_test_cases[] = {
	KUNIT_CASE(tty_unregister_device_skips_a_cleared_slot),
	KUNIT_CASE(tty_unregister_device_releases_a_real_cdev),
	KUNIT_CASE(tty_driver_release_survives_cleared_slots),
	{}
};

static struct kunit_suite tty_test_suite = {
	.name = "tty",
	.test_cases = tty_test_cases,
};
kunit_test_suite(tty_test_suite);

MODULE_DESCRIPTION("KUnit tests for the tty core cdev-slot lifetime");
MODULE_LICENSE("GPL");
