int func(void)
{
	spinlock_t lock;
	spin_lock_irq(&lock);
	printf("Hello\n");
	spin_unlock_irq(&lock);
}

int func2(void)
{
	spinlock_t lock;
	spinlock_t lock2;

	spin_lock_irq(&lock);
	spin_lock_irq(&lock2);
	printf("Hello\n");
	spin_unlock_irq(&lock2);
	spin_lock_irq(&lock2);
	printf("Hello2\n");
	spin_unlock_irq(&lock2);
	spin_unlock_irq(&lock);
}
