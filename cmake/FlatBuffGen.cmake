# ================= Flatbuf Generation =================

set(FLATBUFFER_GENERATED ${PROJECT_SOURCE_DIR}/src/flatbuffer)

make_directory(${FLATBUFFER_GENERATED})

file(GLOB_RECURSE FLATBUF_SRCS ${FLATBUFFER_PATH}/*.fbs)
foreach(FLATBUF_SRC IN LISTS FLATBUF_SRCS)

  # https://www.mankier.com/1/flatc

  # ======================= C++ =========================

  execute_process(
    COMMAND
      ${FLATBUFFER_FLATC} --cpp --gen-object-api --reflect-types --reflect-names
      --gen-json-emit --gen-mutable -I ${FLATBUFFER_PATH} -o
      ${FLATBUFFER_GENERATED} ${FLATBUF_SRC}
    RESULT_VARIABLE FLAT_COMMAND_RESULT)

endforeach(FLATBUF_SRC IN LISTS FLATBUF_SRCS)
