CXX=g++
#CXXFLAGS=-Wall -pedantic-errors -g
CXXFLAGS=-Wall -g
HEADERS=common.h cb1st.h cb1st_handler.h darkshell.h darkshell_handler.h dslserverklr.h dslserverklr_handler.h
SOURCES=main.cpp common.cpp cb1st.cpp cb1st_handler.cpp darkshell.cpp darkshell_handler.cpp dslserverklr.cpp dslserverklr_handler.cpp
OBJECTS=$(SOURCES:.cpp=.o)
LIBS = -pthread -lz
PROGRAM = server

all: $(SOURCES) $(PROGRAM) $(HEADERS)

$(PROGRAM): $(OBJECTS) $(HEADERS)
	$(CXX) -o $@ $(OBJECTS) $(LIBS)

clean:
	rm -f $(OBJECTS) $(PROGRAM)

.cpp.o:
	$(CXX) $(CXXFLAGS) -c -o $@ $<