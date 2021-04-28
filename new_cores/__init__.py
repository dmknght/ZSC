def print_table(headers, *args, **kwargs) -> None:
    """ Print table.
    example:
    Name            Current setting     Description
    ----            ---------------     -----------
    option_name     value               description
    foo             bar                 baz
    foo             bar                 baz
    :param headers: Headers names ex.('Name, 'Current setting', 'Description')
    :param args: table values, each element representing one line ex. ('option_name', 'value', 'description), ...
    :param kwargs: 'extra_fill' space between columns, 'header_separator' character to separate headers from content
    :return:
    """
    extra_fill = kwargs.get("extra_fill", 5)
    header_separator = kwargs.get("header_separator", "-")

    if not all(map(lambda x: len(x) == len(headers), args)):
        print("Headers and table rows tuples should be the same length.")
        return

    def custom_len(x):
        try:
            return len(x)
        except TypeError:
            return 0

    fill = []
    headers_line = '   '
    headers_separator_line = '   '
    for idx, header in enumerate(headers):
        column = [custom_len(arg[idx]) for arg in args]
        column.append(len(header))

        current_line_fill = max(column) + extra_fill
        fill.append(current_line_fill)
        headers_line = "".join((headers_line, "{header:<{fill}}".format(header=header, fill=current_line_fill)))
        headers_separator_line = "".join((
            headers_separator_line,
            "{:<{}}".format(header_separator * len(header), current_line_fill)
        ))

    print()
    print(headers_line)
    print(headers_separator_line)
    for arg in args:
        content_line = "   "
        for idx, element in enumerate(arg):
            content_line = "".join((
                content_line,
                "{:<{}}".format(element, fill[idx])
            ))
        print(content_line)

    print()
