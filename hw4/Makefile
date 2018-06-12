FLAGS =  \
	-Os -s \
	-ffunction-sections \
	-fdata-sections \
	-Wl,--gc-sections \
	-fno-exceptions \
	-fno-rtti \
	-fno-stack-protector \
	-fno-unwind-tables -fno-asynchronous-unwind-tables \
	-fno-math-errno \
	-fno-strict-aliasing \
	-fmerge-all-constants \
	-Wl,-z,norelro \
	-W -Wall \
	-mfpmath=387 -mfancy-math-387 \
	-Wl,--build-id=none  \
	-fno-unroll-loops \
	-fno-ident \
	-fomit-frame-pointer \
	#-ffast-math 
EXE = lanchat
all: main.cpp
	gcc $(FLAGS) main.cpp -o $(EXE)
	strip -S --strip-unneeded --remove-section=.note.gnu.gold-version \
	--remove-section=.comment --remove-section=.note \
	--remove-section=.note.gnu.build-id \
	--remove-section=.note.ABI-tag $(EXE)

