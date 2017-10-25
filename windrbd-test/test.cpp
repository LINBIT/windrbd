#include "gtest/gtest.h"

TEST(example, fail)
{
	ASSERT_TRUE(false);
}

TEST(example, pass)
{
	ASSERT_FALSE(false);
}
