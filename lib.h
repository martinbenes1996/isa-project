/**
 * @brief   Lib.h
 * @author  xbenes49
 * @brief   Global functions and datatypes.
 */

#ifndef LIB_H
#define LIB_H

// C++
#include <string>

/**
 * @brief Prints error and exits.
 * @param error         String to print.
 * @param errcode       Error code.
 */
void printErrorAndExit(std::string error, int errcode) {
    std::cerr << error << "\n";
    exit(errcode);
}

#endif // LIB_H