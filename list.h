/**
 * Minimalistic std::vector-like implementation for C
 * Now with 50% more macros!
 *
 * Example usage:
 *
 * typedef list(int) list_int;
 * int main()
 * {
 *     list_int foo;
 *     list_init(foo);
 *
 *     list_append(foo, 42);
 *     list_insert(foo, 0, 1337);
 *     list_set(foo, 1, 123);
 *
 *     printf("foo[0] = %d\n", list_get(foo, 0));
 *     printf("foo.pop() = %d\n", list_pop(foo));
 *
 *     list_free(foo);
 *     return 0;
 * }
 */

#include <stdlib.h>
#include <string.h>

/**
 * Declares a list of type T. This should be used in conjunction with a
 * typedef at the global scope, as follows:
 *
 * typedef list(int) list_int;
 * typedef list(float) list_float;
 * typedef list(const char *) list_str;
 */
#define list(T) struct {                                                      \
    T *data;                                                                  \
    size_t capacity;                                                          \
    size_t size;                                                              \
}

/**
 * Internal function that returns the greater of two values.
 * Do not call this manually.
 */
#define list_max_(a, b) (((a) > (b)) ? (a) : (b))

/**
 * Internal function for moving elements within the list.
 * Do not call this manually.
 */
#define list_move_(l, to, from, num) do {                                     \
    memmove(&(l).data[(to)], &(l).data[(from)], (num) * sizeof(*(l).data));   \
} while (0)

/**
 * Internal function for resizing the capacity of the list.
 * Do not call this manually.
 */
#define list_realloc_(l, cap) do {                                            \
    (l).capacity = (cap);                                                     \
    (l).data = realloc((l).data, (l).capacity * sizeof(*(l).data));           \
} while (0)

/**
 * Internal function for growing the list when it becomes full.
 * Do not call this manually.
 */
#define list_grow_(l) do {                                                    \
    if ((l).size == (l).capacity) {                                           \
        list_realloc_((l), list_max_((l).capacity * 2, 8));                   \
    }                                                                         \
} while (0)

/**
 * Initializes the specified list. This must only be called once per list.
 */
#define list_init(l) do {                                                     \
    (l).data = NULL;                                                          \
    (l).capacity = 0;                                                         \
    (l).size = 0;                                                             \
} while (0)

/**
 * Frees the specified list. After calling this, the list is
 * invalidated and using it results in undefined behavior.
 */
#define list_free(l) do {                                                     \
    free((l).data);                                                           \
    (l).data = NULL;                                                          \
    (l).capacity = 0;                                                         \
    (l).size = 0;                                                             \
} while (0)

/**
 * Returns the number of elements in the list.
 */
#define list_size(l) ((l).size)

/**
 * Returns the value of the element at the specified index.
 */
#define list_get(l, index) ((l).data[(index)])

/**
 * Sets the value of the element at the specified index.
 */
#define list_set(l, index, value) ((l).data[(index)] = (value))

/**
 * Returns the last element in the list. Undefined behavior when size = 0.
 */
#define list_peek(l) ((l).data[(l).size - 1])

/**
 * Removes and returns the last element in the list. Undefined behavior
 * when size = 0.
 */
#define list_pop(l) ((l).data[--(l).size])

/**
 * Expands the list capacity to at least the specified value.
 * If the new capacity is less than or equal to the current capacity,
 * this has no effect.
 */
#define list_reserve(l, cap) do {                                             \
    if ((cap) > (l).capacity) {                                               \
        list_realloc_((l), (cap));                                            \
    }                                                                         \
} while (0)

/**
 * Trims the list so that its capacity equals its size.
 * Useful for saving memory once you know that no more elements
 * will be added to the list.
 */
#define list_trim(l) do {                                                     \
    list_realloc_((l), (l).size);                                             \
} while (0)

/**
 * Resizes the list to the specified size. If the new size is
 * greater than the old size, the new elements have undefined
 * initial values.
 */
#define list_resize(l, sz) do {                                               \
    list_reserve((l), (sz));                                                  \
    (l).size = (sz);                                                          \
} while (0)

/**
 * Appends the given value to the end of the list.
 */
#define list_append(l, value) do {                                            \
    list_grow_((l));                                                          \
    (l).data[(l).size++] = (value);                                           \
} while (0)

/**
 * Inserts the given value at the specified index.
 */
#define list_insert(l, index, value) do {                                     \
    list_grow_((l));                                                          \
    list_move_((l), (index) + 1, (index), (l).size - (index));                \
    (l).data[(index)] = (value);                                              \
    (l).size++;                                                               \
} while (0)

/**
 * Removes the value at the specified index and shifts the
 * remaining elements left.
 */
#define list_remove(l, index) do {                                            \
    list_move_((l), (index), (index) + 1, (l).size - (index) - 1);            \
    (l).size--;                                                               \
} while (0)

/**
 * Removes all elements from the list.
 */
#define list_clear(l) do {                                                    \
    (l).size = 0;                                                             \
} while (0)
