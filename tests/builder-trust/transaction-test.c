#include "iu_builder_transaction.h"
#include <stdio.h>

int main(void) {
    uint8_t input[IU_BUILDER_TRANSACTION_MAX_BYTES + 1], output[IU_BUILDER_TRANSACTION_MAX_BYTES];
    struct iu_builder_transaction_v1 transaction;
    size_t length = fread(input, 1, sizeof(input), stdin), output_length = 0;
    if (ferror(stdin) || iu_builder_transaction_parse_v1(input, length, &transaction) != IU_BUILDER_OK) return 1;
    if (iu_builder_transaction_encode_v1(&transaction, output, sizeof(output), &output_length) != IU_BUILDER_OK) return 2;
    if (fwrite(output, 1, output_length, stdout) != output_length) return 3;
    return 0;
}
