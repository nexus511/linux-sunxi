#include <linux/acpi.h>
#include <linux/gpio/consumer.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/thermal.h>
#include <linux/workqueue.h>

#include <linux/io.h>

#define GPIOFANADR1      0xfed8c400
#define GPIOFANADR2      0xfed8c408

struct gpd_pocket_fan_data {
	unsigned int *gpd0con;
	unsigned int *gpd1con;
	struct delayed_work work;
	int last_speed;
	struct thermal_zone_device *dts0;
	struct thermal_zone_device *dts1;
};

static void gpd_pocket_fan_set_speed(struct gpd_pocket_fan_data *fan, int speed)
{
	if (speed == fan->last_speed)
		return;
	if (speed & 1)
		writel(readl(fan->gpd0con) | 2, fan->gpd0con);
	else
		writel(readl(fan->gpd0con) & ~0x2UL, fan->gpd0con);

	if (speed & 2)
		writel(readl(fan->gpd1con) | 2, fan->gpd1con);
	else
		writel(readl(fan->gpd1con) & ~0x2UL, fan->gpd1con);

	fan->last_speed = speed;
}

static void gpd_pocket_fan_worker(struct work_struct *work)
{
	struct gpd_pocket_fan_data *fan =
		container_of(work, struct gpd_pocket_fan_data, work.work);
	int t0, t1, temp, speed, i;
	const int temp_limits[] = { 55000, 60000, 65000 };

	if (thermal_zone_get_temp(fan->dts0, &t0) ||
	    thermal_zone_get_temp(fan->dts1, &t1))
		return;

	temp = max(t0, t1);

	speed = fan->last_speed;

	/* Determine minimum speed */
	for (i = 0; i < ARRAY_SIZE(temp_limits); i++) {
		if (temp < temp_limits[i])
			break;
	}
	if (speed < i)
		speed = i;

	/* Use 3 degrees hysteresis before lowering speed again */
	for (i = 0; i < ARRAY_SIZE(temp_limits); i++) {
		if (temp < (temp_limits[i] - 3000))
			break;
	}
	if (speed > i)
		speed = i;

	if (fan->last_speed <= 0 && speed)
		speed = 3; /* kick start motor */

	pr_err("gpd_pocket_fan: temp=%d new speed=%d\n", temp, speed);
	gpd_pocket_fan_set_speed(fan, speed);

	/* When mostly idle (temp below 45), slow down the poll interval. */
	i = temp < 45000 ? 5000 : 1000;
	queue_delayed_work(system_wq, &fan->work, msecs_to_jiffies(i));
}

static void gpd_pocket_fan_force_update(struct gpd_pocket_fan_data *fan)
{
	fan->last_speed = -1;
	mod_delayed_work(system_wq, &fan->work, 0);
}

static int gpd_pocket_fan_probe(struct platform_device *pdev)
{
	struct gpd_pocket_fan_data *fan;

	fan = devm_kzalloc(&pdev->dev, sizeof(*fan), GFP_KERNEL);
	if (!fan)
		return -ENOMEM;

	/* Note this returns a "weak" reference which we don't need to free */
	fan->dts0 = thermal_zone_get_zone_by_name("soc_dts0");
	if (!fan->dts0)
		return -EPROBE_DEFER;

	fan->dts1 = thermal_zone_get_zone_by_name("soc_dts1");
	if (!fan->dts1)
		return -EPROBE_DEFER;

	fan->gpd0con = ioremap(GPIOFANADR1, 4);
	fan->gpd1con = ioremap(GPIOFANADR2, 4);
	INIT_DELAYED_WORK(&fan->work, gpd_pocket_fan_worker);

	gpd_pocket_fan_force_update(fan);

	platform_set_drvdata(pdev, fan);
	return 0;
}

static int gpd_pocket_fan_remove(struct platform_device *pdev)
{
	struct gpd_pocket_fan_data *fan = platform_get_drvdata(pdev);

	cancel_delayed_work_sync(&fan->work);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int gpd_pocket_fan_suspend(struct device *dev)
{
	struct gpd_pocket_fan_data *fan = dev_get_drvdata(dev);

	gpd_pocket_fan_set_speed(fan, 0);
	return 0;
}

static int gpd_pocket_fan_resume(struct device *dev)
{
	struct gpd_pocket_fan_data *fan = dev_get_drvdata(dev);

	gpd_pocket_fan_force_update(fan);

	return 0;
}
#endif
static SIMPLE_DEV_PM_OPS(gpd_pocket_fan_pm_ops,
			 gpd_pocket_fan_suspend,
			 gpd_pocket_fan_resume);

static struct acpi_device_id gpd_pocket_fan_acpi_match[] = {
	{ "FAN02501" },
	{},
};
MODULE_DEVICE_TABLE(acpi, gpd_pocket_fan_acpi_match);

static struct platform_driver gpd_pocket_fan_driver = {
	.probe	= gpd_pocket_fan_probe,
	.remove	= gpd_pocket_fan_remove,
	.driver	= {
		.name			= "gpd_pocket_fan",
		.acpi_match_table	= gpd_pocket_fan_acpi_match,
		.pm			= &gpd_pocket_fan_pm_ops,
	 },
};

module_platform_driver(gpd_pocket_fan_driver);
MODULE_AUTHOR("Hans de Goede <hdegoede@redhat.com");
MODULE_DESCRIPTION("GPD pocket fan driver");
MODULE_LICENSE("GPL");
