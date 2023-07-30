uftrace에 기여하기
==================

uftrace에 기여하는 것을 고려해주셔서 감사합니다.
아래의 주소에서 uftrace 소스코드를 git으로 클론한 뒤 패치와 함께 PR을 보내주시면 됩니다.
패치를 진행하시기에 앞서, 본 글에 소개된 규칙들을 먼저 읽어주시기를 권장드립니다.

  https://github.com/namhyung/uftrace


코드 작성 스타일
----------------

uftrace는 C로 작성되었고 몇가지 차이점들을 제외하고서는 거의 대부분
[리눅스 커널의 코드 작성  스타일](https://www.kernel.org/doc/Documentation/process/coding-style.rst)을 따르고 있습니다.

uftrace 저장소에서는 [pre-commit](https://pre-commit.com)과 [clang-format](https://clang.llvm.org/docs/ClangFormat.html)을 통해
자동으로 코드 형식을 적용시켜 전반적인 소스코드의 코드 작성 스타일이 항상 일관적으로 유지될 수 있도록 하고 있습니다.

코드 작성 스타일을 자동으로 검사하기 위해서는 pre-commit 파이썬 패키지 (파이썬 버전 3.7 이상이 필요합니다)가 필요하고,
설치는 다음과 같이 진행할 수 있습니다.

    $ python3 -m pip install pre-commit

패키지 설치가 완료되었다면, pre-commit hook을 uftrace 소스코드 디렉토리 안에 설치할 수 있습니다.

    $ pre-commit install
    pre-commit installed at .git/hooks/pre-commit

디렉토리 안에 pre-commit 설치가 완료되었다면,
새로운 commit을 작성할 때마다 코드 작성 스타일이 자동으로 검사될 것입니다.

    $ git commit -s
        ...
    clang-format.............................................................Failed
    - hook id: clang-format
    - files were modified by this hook

만약, 작성된 코드가 uftrace의 코드 작성 스타일과 맞지 않는다면
clang-format이 코딩 스타일을 검사한 결과가 Failed로 나타나고,
[.clang-format](.clang-format)에 미리 설정해둔 코드 작성 스타일에 맞추어 코드가 자동으로 수정될 것입니다.

clang-format으로 코드가 수정되었다면, `git add -u` 명령어를 실행한 뒤,
commit을 다시 작성해서 수정된 코드가 반영될 수 있도록 해야합니다.

다음의 명령어로 pre-commit을 사용한 코드 작성 스타일 검사도 가능합니다.

    $ git add -u
    $ pre-commit run

pre-commit은 git staging된 코드들에 한해서 코드 작성 스타일을 검사하고,
검사 결과가 Failed로 나타나면 자동으로 코드 스타일을 수정해줍니다.


패치 주제를 메시지 제목에 포함시키기
------------------------------------

uftrace가 큰 규모의 프로젝트가 아닐지라도,
쌍점(:) 앞에 패치의 주제를 나타내는 단어를 적는 것은
다른 개발자들이 여러 주제의 패치를 쉽게 구분할 수 있게 해주는 좋은 규칙이라고 생각됩니다.

    $ git log --oneline --graph
    *   fef4226 Merge branch 'misc-fix'
    |\
    | * 54a4ef0 test: Fix to be able to call runtest.py directly
    | * 6bbe4a0 graph: Skip kernel functions outside of user
    | * a76c7cb kernel: Use real address for filter match
    |/
    ...


패치에 서명하기
---------------

sign-off (서명)은 패치에 대한 설명 마지막 부분에 한줄로
패치를 자신이 직접 작성했고, 오픈소스 패치로 배포할 권리가 있다는 사실을 알려주는 것입니다.
패치에 sign-off (서명)을 하는 규칙은 [다음 항목](https://developercertificate.org/)들에 동의하는 것으로 충분합니다:

		Developer's Certificate of Origin 1.1

		본 프로젝트의 기여자로써, 다음을 증명합니다:

		(a) 본 프로젝트에 대한 전체 혹은 일부 기여는 본인이 직접 했으며,
			기여자 본인은 파일에 명시되어 있는 오픈소스 라이센스에 따라 기여한 부분을 제출할 권리가 있습니다.

		(b) 본 프로젝트에 대한 기여는, 기여자 본인이 아는 한,
			적절한 오픈소스 라이센스가 적용되는 이전 작업들에 기반하고 있으며
			다른 라이센스를 사용하는 것이 허용되지 않은 이상,
			파일에 명시된 바에 따라, 기여자 본인은 동일한 오픈소스 라이센스에 기반하여
			이전 작업들을 전체 또는 일부 수정하여 제출할 권리가 있습니다.

		(c) 본 프로젝트에 대한 기여는 상기 (a), (b), (c) 중 하나의 항목에 해당되는 이로부터 직접 제공받았으며,
			본인은 제공받은 작업물을 수정하지 않았습니다.

		(d) 본 프로젝트 및 기여자가 프로젝트에 기여한 부분은 공개되는 바이며,
			프로젝트에 기여한 부분을 제출할 때 함께 제공했던 개인정보와 서명(sign-off)과 같은 기록들은
			무기한 유지되어 본 프로젝트나 프로젝트와 관련된 오픈소스 라이센스와 함께
			지속적으로 재배포 될 수 있음을 이해하고 동의합니다.

본인이 위 항목 (a), (b), (c) 중 하나에 해당되고 (d)에 동의한다면,
패치 설명 마지막 부분에 본인의 실명으로 다음과 같이 한 줄을 추가해주시면 됩니다.
(가명이나 익명으로 프로젝트에 기여하는 것은 허용하지 않습니다.)

	Signed-off-by: Random J Developer <random@developer.example.org>
